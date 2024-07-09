using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.LDAPQueries;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.Processors;
using SharpHoundRPC.NetAPINative;
using Domain = System.DirectoryServices.ActiveDirectory.Domain;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;
using SecurityMasks = System.DirectoryServices.Protocols.SecurityMasks;

namespace SharpHoundCommonLib
{
    public class LdapUtils : ILdapUtils
    {
        //This cache is indexed by domain sid
        private readonly ConcurrentDictionary<string, NetAPIStructs.DomainControllerInfo?> _dcInfoCache = new();
        private static readonly ConcurrentDictionary<string, Domain> DomainCache = new();
        private static readonly ConcurrentDictionary<string, byte> DomainControllers = new();

        private static readonly ConcurrentDictionary<string, string> DomainToForestCache =
            new(StringComparer.OrdinalIgnoreCase);

        private static readonly ConcurrentDictionary<string, ResolvedWellKnownPrincipal>
            SeenWellKnownPrincipals = new();

        private readonly ConcurrentDictionary<string, string> _hostResolutionMap = new(StringComparer.OrdinalIgnoreCase);

        private readonly ConcurrentDictionary<string, TypedPrincipal> _distinguishedNameCache =
            new(StringComparer.OrdinalIgnoreCase);

        private readonly ILogger _log;
        private readonly PortScanner _portScanner;
        private readonly NativeMethods _nativeMethods;
        private readonly string _nullCacheKey = Guid.NewGuid().ToString();
        private readonly Regex _sidRegex = new(@"^(S-\d+-\d+-\d+-\d+-\d+-\d+)-\d+$");

        private readonly string[] _translateNames = { "Administrator", "admin" };
        private LDAPConfig _ldapConfig = new();

        private ConnectionPoolManager _connectionPool;

        private static readonly TimeSpan MinBackoffDelay = TimeSpan.FromSeconds(2);
        private static readonly TimeSpan MaxBackoffDelay = TimeSpan.FromSeconds(20);
        private const int BackoffDelayMultiplier = 2;
        private const int MaxRetries = 3;

        private static readonly byte[] NameRequest = {
            0x80, 0x94, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
            0x00, 0x01
        };

        private class ResolvedWellKnownPrincipal
        {
            public string DomainName { get; set; }
            public string WkpId { get; set; }
        }

        public LdapUtils()
        {
            _nativeMethods = new NativeMethods();
            _portScanner = new PortScanner();
            _log = Logging.LogProvider.CreateLogger("LDAPUtils");
            _connectionPool = new ConnectionPoolManager(_ldapConfig, _log);
        }

        public LdapUtils(NativeMethods nativeMethods = null, PortScanner scanner = null, ILogger log = null)
        {
            _nativeMethods = nativeMethods ?? new NativeMethods();
            _portScanner = scanner ?? new PortScanner();
            _log = log ?? Logging.LogProvider.CreateLogger("LDAPUtils");
            _connectionPool = new ConnectionPoolManager(_ldapConfig, scanner: _portScanner);
        }

        public async IAsyncEnumerable<Result<string>> RangedRetrieval(
        string distinguishedName,
        string attributeName,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            var domain = Helpers.DistinguishedNameToDomain(distinguishedName);
            var connectionResult = await _connectionPool.GetLdapConnection(domain, globalCatalog: false);
            if (!connectionResult.Success)
            {
                yield return Result<string>.Fail(connectionResult.Message);
                yield break;
            }

            var connectionWrapper = connectionResult.ConnectionWrapper;
            var queryParameters = CreateQueryParameters(domain, attributeName, distinguishedName);
            if (!CreateSearchRequest(queryParameters, connectionWrapper, out var searchRequest))
            {
                _connectionPool.ReleaseConnection(connectionWrapper);
                yield return Result<string>.Fail("Failed to create search request");
                yield break;
            }

            await foreach (var result in ExecuteRangedRetrieval(connectionWrapper, searchRequest, queryParameters, cancellationToken))
            {
                yield return result;
            }

            _connectionPool.ReleaseConnection(connectionWrapper);
        }

        private LdapQueryParameters CreateQueryParameters(string domain, string attributeName, string distinguishedName)
        {
            return new LdapQueryParameters
            {
                DomainName = domain,
                LDAPFilter = $"{attributeName}=*",
                //Start by using * as our upper index, which will automatically give us the range size
                Attributes = new[] { $"{attributeName};range=0-*" },
                SearchScope = SearchScope.Base,
                SearchBase = distinguishedName
            };
        }

        private async IAsyncEnumerable<Result<string>> ExecuteRangedRetrieval(
            LdapConnectionWrapper connectionWrapper,
            SearchRequest searchRequest,
            LdapQueryParameters queryParameters,
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            int index = 0;
            int step = 0;
            bool complete = false;

            while (!cancellationToken.IsCancellationRequested && !complete)
            {
                var response = await ExecuteSearchRequest(connectionWrapper, searchRequest, queryParameters, cancellationToken);
                if (!response.IsSuccess)
                {
                    yield return Result<string>.Fail(response.Error);
                    yield break;
                }

                var entry = response.Value.Entries[0];
                complete = UpdateRangeInfo(entry, ref index, ref searchRequest);

                foreach (string dn in entry.Attributes[searchRequest.Attributes[0]].GetValues(typeof(string)))
                {
                    yield return Result<string>.Ok(dn);
                }
            }
        }

        private async Task<Result<SearchResponse>> ExecuteSearchRequest(
            LdapConnectionWrapper connectionWrapper,
            SearchRequest searchRequest,
            LdapQueryParameters queryParameters,
            CancellationToken cancellationToken)
        {
            int busyRetryCount = 0;
            int queryRetryCount = 0;

            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    var response = (SearchResponse)connectionWrapper.Connection.SendRequest(searchRequest);
                    return Result<SearchResponse>.Ok(response);
                }
                catch (LdapException le) when (le.ErrorCode == (int)ResultCode.Busy && busyRetryCount < MaxRetries)
                {
                    await HandleBusyException(++busyRetryCount);
                }
                catch (LdapException le) when (le.ErrorCode == (int)LdapErrorCodes.ServerDown && queryRetryCount < MaxRetries)
                {
                    queryRetryCount++;
                    var result = await HandleServerDownException(connectionWrapper, queryParameters.DomainName);
                    if (!result.IsSuccess)
                    {
                        return Result<SearchResponse>.Fail(result.Error);
                    }
                    connectionWrapper = result.Value;
                }
                catch (LdapException le)
                {
                    return Result<SearchResponse>.Fail($"Unrecoverable LDAP exception: {le.Message} (ServerMessage: {le.ServerErrorMessage}) (ErrorCode: {le.ErrorCode})");
                }
                catch (Exception e)
                {
                    return Result<SearchResponse>.Fail($"Unrecoverable exception: {e.Message}");
                }
            }

            return Result<SearchResponse>.Fail("Cancellation requested, exiting.");
        }

        private async Task HandleBusyException(int retryCount)
        {
            var backoffDelay = GetNextBackoff(retryCount);
            await Task.Delay(backoffDelay);
        }

        private async Task<Result<LdapConnectionWrapper>> HandleServerDownException(LdapConnectionWrapper oldConnection, string domain)
        {
            _connectionPool.ReleaseConnection(oldConnection, connectionFaulted: true);

            for (int retryCount = 0; retryCount < MaxRetries; retryCount++)
            {
                var backoffDelay = GetNextBackoff(retryCount);
                await Task.Delay(backoffDelay);

                var (success, newConnectionWrapper, message) = await _connectionPool.GetLdapConnection(domain, false);
                if (success)
                {
                    _log.LogDebug("RangedRetrieval - Recovered from ServerDown successfully, connection made to {NewServer}", newConnectionWrapper.GetServer());
                    return Result<LdapConnectionWrapper>.Ok(newConnectionWrapper);
                }
            }

            _log.LogError("RangedRetrieval - Failed to get a new connection after ServerDown for domain {Domain}", domain);
            return Result<LdapConnectionWrapper>.Fail("Failed to get a new connection after ServerDown.");
        }

        private bool UpdateRangeInfo(SearchResultEntry entry, ref int index, ref SearchRequest searchRequest)
        {
            string currentRange = entry.Attributes.AttributeNames.First();
            bool complete = currentRange.IndexOf("*", 0, StringComparison.OrdinalIgnoreCase) > 0;
            int step = entry.Attributes[currentRange].Count;

            index += step;
            if (!complete)
            {
                string newRange = $"{currentRange.Split(';')[0]};range={index}-{index + step}";
                searchRequest.Attributes.Clear();
                searchRequest.Attributes.Add(newRange);
            }

            return complete;
        }

        public async IAsyncEnumerable<LdapResult<ISearchResultEntry>> Query(
        LdapQueryParameters queryParameters,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            var setupResult = await SetupLdapQuery(queryParameters);
            if (!setupResult.Success)
            {
                _log.LogInformation("Query - Failure during query setup: {Reason}\n{Info}", setupResult.SearchRequest, queryParameters.GetQueryInfo());
                yield break;
            }

            if (cancellationToken.IsCancellationRequested)
            {
                _connectionPool.ReleaseConnection(setupResult.ConnectionWrapper);
                yield break;
            }

            var queryResult = await ExecuteQuery(setupResult.SearchRequest, setupResult.ConnectionWrapper, queryParameters, cancellationToken);
            _connectionPool.ReleaseConnection(setupResult.ConnectionWrapper, queryResult.ErrorCode == (int)LdapErrorCodes.ServerDown);

            if (!queryResult.Success)
            {
                yield return LdapResult<ISearchResultEntry>.Fail(queryResult.ErrorMessage, queryParameters, queryResult.ErrorCode);
                yield break;
            }

            foreach (SearchResultEntry entry in queryResult.Response.Entries)
            {
                yield return LdapResult<ISearchResultEntry>.Ok(new SearchResultEntryWrapper(entry, this));
            }
        }

        public async IAsyncEnumerable<LdapResult<ISearchResultEntry>> PagedQuery(
            LdapQueryParameters queryParameters,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            var setupResult = await SetupLdapQuery(queryParameters);
            if (!setupResult.Success)
            {
                _log.LogInformation("PagedQuery - Failure during query setup: {Reason}\n{Info}", setupResult.SearchRequest, queryParameters.GetQueryInfo());
                yield break;
            }

            var pageControl = new PageResultRequestControl(500);
            setupResult.SearchRequest.Controls.Add(pageControl);

            while (!cancellationToken.IsCancellationRequested)
            {
                var queryResult = await ExecutePagedQuery(setupResult.SearchRequest, setupResult.ConnectionWrapper, setupResult.Server, queryParameters, cancellationToken);

                if (!queryResult.Success)
                {
                    _connectionPool.ReleaseConnection(setupResult.ConnectionWrapper, queryResult.ErrorCode == (int)LdapErrorCodes.ServerDown);
                    yield return LdapResult<ISearchResultEntry>.Fail(queryResult.ErrorMessage, queryParameters, queryResult.ErrorCode);
                    yield break;
                }

                foreach (SearchResultEntry entry in queryResult.Response.Entries)
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        _connectionPool.ReleaseConnection(setupResult.ConnectionWrapper);
                        yield break;
                    }

                    yield return LdapResult<ISearchResultEntry>.Ok(new SearchResultEntryWrapper(entry, this));
                }

                var pageResponse = (PageResultResponseControl)queryResult.Response.Controls
                    .FirstOrDefault(x => x is PageResultResponseControl);

                if (pageResponse?.Cookie.Length == 0 || queryResult.Response.Entries.Count == 0)
                {
                    _connectionPool.ReleaseConnection(setupResult.ConnectionWrapper);
                    yield break;
                }

                pageControl.Cookie = pageResponse.Cookie;
            }

            _connectionPool.ReleaseConnection(setupResult.ConnectionWrapper);
        }

        private async Task<QueryResult> ExecuteQuery(SearchRequest searchRequest, LdapConnectionWrapper connectionWrapper, LdapQueryParameters queryParameters, CancellationToken cancellationToken)
        {
            int queryRetryCount = 0;
            int busyRetryCount = 0;

            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    _log.LogTrace("Sending ldap request - {Info}", queryParameters.GetQueryInfo());
                    var response = (SearchResponse)connectionWrapper.Connection.SendRequest(searchRequest);
                    return new QueryResult { Success = true, Response = response };
                }
                catch (LdapException le) when (le.ErrorCode == (int)LdapErrorCodes.ServerDown && queryRetryCount < MaxRetries)
                {
                    var newConnection = await HandleServerDownException(connectionWrapper, null);
                    if (newConnection != null)
                    {
                        connectionWrapper = newConnection.Value;
                    }
                    else
                    {
                        return new QueryResult { Success = false, ErrorMessage = "Failed to get a new connection after ServerDown.", ErrorCode = le.ErrorCode };
                    }
                }
                catch (LdapException le) when (le.ErrorCode == (int)ResultCode.Busy && busyRetryCount < MaxRetries)
                {
                    await HandleBusyException(++busyRetryCount);
                }
                catch (LdapException le)
                {
                    return new QueryResult { Success = false, ErrorMessage = $"Query - Caught unrecoverable ldap exception: {le.Message} (ServerMessage: {le.ServerErrorMessage}) (ErrorCode: {le.ErrorCode})", ErrorCode = le.ErrorCode };
                }
                catch (Exception e)
                {
                    return new QueryResult { Success = false, ErrorMessage = $"Query - Caught unrecoverable exception: {e.Message}" };
                }
            }

            return new QueryResult { Success = false, ErrorMessage = "Query cancelled" };
        }

        private async Task<QueryResult> ExecutePagedQuery(SearchRequest searchRequest, LdapConnectionWrapper connectionWrapper, string serverName, LdapQueryParameters queryParameters, CancellationToken cancellationToken)
        {
            int busyRetryCount = 0;
            int queryRetryCount = 0;

            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    _log.LogTrace("Sending paged ldap request - {Info}", queryParameters.GetQueryInfo());
                    var response = (SearchResponse)connectionWrapper.Connection.SendRequest(searchRequest);
                    return new QueryResult { Success = true, Response = response };
                }
                catch (LdapException le) when (le.ErrorCode == (int)LdapErrorCodes.ServerDown)
                {
                    if (string.IsNullOrEmpty(serverName))
                    {
                        _log.LogError("PagedQuery - Received server down exception without a known servername. Unable to generate new connection\n{Info}", queryParameters.GetQueryInfo());
                        return new QueryResult { Success = false, ErrorMessage = "ServerDown exception without known server name", ErrorCode = le.ErrorCode };
                    }

                    var newConnection = await HandleServerDownException(connectionWrapper, serverName);
                    if (newConnection != null)
                    {
                        connectionWrapper = newConnection.Value;
                    }
                    else
                    {
                        return new QueryResult { Success = false, ErrorMessage = "Failed to get a new connection after ServerDown.", ErrorCode = le.ErrorCode };
                    }
                }
                catch (LdapException le) when (le.ErrorCode == (int)ResultCode.Busy && busyRetryCount < MaxRetries)
                {
                    await HandleBusyException(++busyRetryCount);
                }
                catch (LdapException le)
                {
                    return new QueryResult { Success = false, ErrorMessage = $"PagedQuery - Caught unrecoverable ldap exception: {le.Message} (ServerMessage: {le.ServerErrorMessage}) (ErrorCode: {le.ErrorCode})", ErrorCode = le.ErrorCode };
                }
                catch (Exception e)
                {
                    return new QueryResult { Success = false, ErrorMessage = $"PagedQuery - Caught unrecoverable exception: {e.Message}" };
                }
            }

            return new QueryResult { Success = false, ErrorMessage = "PagedQuery cancelled" };
        }


        public async Task<(bool Success, TypedPrincipal Principal)> ResolveIDAndType(SecurityIdentifier securityIdentifier,
            string objectDomain)
        {
            return await ResolveIDAndType(securityIdentifier.Value, objectDomain);
        }

        public async Task<(bool Success, TypedPrincipal Principal)>
            ResolveIDAndType(string identifier, string objectDomain)
        {
            if (identifier.Contains("0ACNF"))
            {
                return (false, new TypedPrincipal(identifier, Label.Base));
            }

            if (await GetWellKnownPrincipal(identifier, objectDomain) is (true, var principal))
            {
                return (true, principal);
            }

            if (identifier.StartsWith("S-"))
            {
                var result = await LookupSidType(identifier, objectDomain);
                return (result.Success, new TypedPrincipal(identifier, result.Type));
            }

            var (success, type) = await LookupGuidType(identifier, objectDomain);
            return (success, new TypedPrincipal(identifier, type));
        }

        private async Task<(bool Success, Label Type)> LookupSidType(string sid, string domain)
        {
            if (Cache.GetIDType(sid, out var type))
            {
                return (true, type);
            }

            var tempDomain = domain;

            if (await GetDomainNameFromSid(sid) is (true, var domainName))
            {
                tempDomain = domainName;
            }

            var result = await Query(new LdapQueryParameters()
            {
                DomainName = tempDomain,
                LDAPFilter = CommonFilters.SpecificSID(sid),
                Attributes = CommonProperties.TypeResolutionProps
            }).DefaultIfEmpty(LdapResult<ISearchResultEntry>.Fail()).FirstOrDefaultAsync();

            if (result.IsSuccess)
            {
                type = result.Value.GetLabel();
                Cache.AddType(sid, type);
                return (true, type);
            }

            try
            {
                var entry = new DirectoryEntry($"LDAP://<SID={sid}>");
                if (entry.GetLabel(out type))
                {
                    Cache.AddType(sid, type);
                    return (true, type);
                }
            }
            catch
            {
                //pass
            }

            using (var ctx = new PrincipalContext(ContextType.Domain))
            {
                try
                {
                    var principal = Principal.FindByIdentity(ctx, IdentityType.Sid, sid);
                    if (principal != null)
                    {
                        var entry = (DirectoryEntry)principal.GetUnderlyingObject();
                        if (entry.GetLabel(out type))
                        {
                            Cache.AddType(sid, type);
                            return (true, type);
                        }
                    }
                }
                catch
                {
                    //pass
                }
            }

            return (false, Label.Base);
        }

        private async Task<(bool Success, Label type)> LookupGuidType(string guid, string domain)
        {
            if (Cache.GetIDType(guid, out var type))
            {
                return (true, type);
            }

            var result = await Query(new LdapQueryParameters()
            {
                DomainName = domain,
                LDAPFilter = CommonFilters.SpecificGUID(guid),
                Attributes = CommonProperties.TypeResolutionProps
            }).DefaultIfEmpty(LdapResult<ISearchResultEntry>.Fail()).FirstOrDefaultAsync();

            if (result.IsSuccess)
            {
                type = result.Value.GetLabel();
                Cache.AddType(guid, type);
                return (true, type);
            }

            try
            {
                var entry = new DirectoryEntry($"LDAP://<GUID={guid}>");
                if (entry.GetLabel(out type))
                {
                    Cache.AddType(guid, type);
                    return (true, type);
                }
            }
            catch
            {
                //pass
            }

            using (var ctx = new PrincipalContext(ContextType.Domain))
            {
                try
                {
                    var principal = Principal.FindByIdentity(ctx, IdentityType.Guid, guid);
                    if (principal != null)
                    {
                        var entry = (DirectoryEntry)principal.GetUnderlyingObject();
                        if (entry.GetLabel(out type))
                        {
                            Cache.AddType(guid, type);
                            return (true, type);
                        }
                    }
                }
                catch
                {
                    //pass
                }
            }

            return (false, Label.Base);
        }

        public async Task<(bool Success, TypedPrincipal WellKnownPrincipal)> GetWellKnownPrincipal(
            string securityIdentifier, string objectDomain)
        {
            if (!WellKnownPrincipal.GetWellKnownPrincipal(securityIdentifier, out var wellKnownPrincipal))
            {
                return (false, null);
            }

            var (newIdentifier, newDomain) = await GetWellKnownPrincipalObjectIdentifier(securityIdentifier, objectDomain);

            wellKnownPrincipal.ObjectIdentifier = newIdentifier;
            SeenWellKnownPrincipals.TryAdd(wellKnownPrincipal.ObjectIdentifier, new ResolvedWellKnownPrincipal
            {
                DomainName = newDomain,
                WkpId = securityIdentifier
            });

            return (true, wellKnownPrincipal);
        }

        private async Task<(string ObjectID, string Domain)> GetWellKnownPrincipalObjectIdentifier(
            string securityIdentifier, string domain)
        {
            if (!WellKnownPrincipal.GetWellKnownPrincipal(securityIdentifier, out _))
                return (securityIdentifier, string.Empty);

            if (!securityIdentifier.Equals("S-1-5-9", StringComparison.OrdinalIgnoreCase))
            {
                var tempDomain = domain;
                if (GetDomain(tempDomain, out var domainObject) && domainObject.Name != null)
                {
                    tempDomain = domainObject.Name;
                }

                return ($"{tempDomain}-{securityIdentifier}".ToUpper(), tempDomain);
            }

            if (await GetForest(domain) is (true, var forest))
            {
                return ($"{forest}-{securityIdentifier}".ToUpper(), forest);
            }

            _log.LogWarning("Failed to get a forest name for domain {Domain}, unable to resolve enterprise DC sid", domain);
            return ($"UNKNOWN-{securityIdentifier}", "UNKNOWN");
        }

        private async Task<(bool Success, string ForestName)> GetForest(string domain)
        {
            if (DomainToForestCache.TryGetValue(domain, out var cachedForest))
            {
                return (true, cachedForest);
            }

            if (GetDomain(domain, out var domainObject))
            {
                try
                {
                    var forestName = domainObject.Forest.Name.ToUpper();
                    DomainToForestCache.TryAdd(domain, forestName);
                    return (true, forestName);
                }
                catch
                {
                    //pass
                }
            }

            var (success, forest) = await GetForestFromLdap(domain);
            if (success)
            {
                DomainToForestCache.TryAdd(domain, forest);
                return (true, forest);
            }

            return (false, null);
        }

        private async Task<(bool Success, string ForestName)> GetForestFromLdap(string domain)
        {
            var queryParameters = new LdapQueryParameters
            {
                Attributes = new[] { LDAPProperties.RootDomainNamingContext },
                SearchScope = SearchScope.Base,
                DomainName = domain,
                LDAPFilter = new LDAPFilter().AddAllObjects().GetFilter(),
            };

            var result = await Query(queryParameters).FirstAsync();
            if (result.IsSuccess)
            {
                var rdn = result.Value.GetProperty(LDAPProperties.RootDomainNamingContext);
                if (!string.IsNullOrEmpty(rdn))
                {
                    return (true, Helpers.DistinguishedNameToDomain(rdn).ToUpper());
                }
            }

            return (false, null);
        }

        private static TimeSpan GetNextBackoff(int retryCount)
        {
            return TimeSpan.FromSeconds(Math.Min(
                MinBackoffDelay.TotalSeconds * Math.Pow(BackoffDelayMultiplier, retryCount),
                MaxBackoffDelay.TotalSeconds));
        }

        private bool CreateSearchRequest(LdapQueryParameters queryParameters,
            LdapConnectionWrapper connectionWrapper, out SearchRequest searchRequest)
        {
            string basePath;
            if (!string.IsNullOrWhiteSpace(queryParameters.SearchBase))
            {
                basePath = queryParameters.SearchBase;
            }
            else if (!connectionWrapper.GetSearchBase(queryParameters.NamingContext, out basePath))
            {
                string tempPath;
                if (CallDsGetDcName(queryParameters.DomainName, out var info) && info != null)
                {
                    tempPath = Helpers.DomainNameToDistinguishedName(info.Value.DomainName);
                    connectionWrapper.SaveContext(queryParameters.NamingContext, basePath);
                }
                else if (GetDomain(queryParameters.DomainName, out var domainObject))
                {
                    tempPath = Helpers.DomainNameToDistinguishedName(domainObject.Name);
                }
                else
                {
                    searchRequest = null;
                    return false;
                }

                basePath = queryParameters.NamingContext switch
                {
                    NamingContext.Configuration => $"CN=Configuration,{tempPath}",
                    NamingContext.Schema => $"CN=Schema,CN=Configuration,{tempPath}",
                    NamingContext.Default => tempPath,
                    _ => throw new ArgumentOutOfRangeException()
                };

                connectionWrapper.SaveContext(queryParameters.NamingContext, basePath);

                if (!string.IsNullOrWhiteSpace(queryParameters.RelativeSearchBase))
                {
                    basePath = $"{queryParameters.RelativeSearchBase},{basePath}";
                }
            }

            searchRequest = new SearchRequest(basePath, queryParameters.LDAPFilter, queryParameters.SearchScope,
                queryParameters.Attributes);
            searchRequest.Controls.Add(new SearchOptionsControl(SearchOption.DomainScope));
            if (queryParameters.IncludeDeleted)
            {
                searchRequest.Controls.Add(new ShowDeletedControl());
            }

            if (queryParameters.IncludeSecurityDescriptor)
            {
                searchRequest.Controls.Add(new SecurityDescriptorFlagControl
                {
                    SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner
                });
            }

            return true;
        }

        private bool CallDsGetDcName(string domainName, out NetAPIStructs.DomainControllerInfo? info)
        {
            if (_dcInfoCache.TryGetValue(domainName.ToUpper().Trim(), out info)) return info != null;

            var apiResult = _nativeMethods.CallDsGetDcName(null, domainName,
                (uint)(NetAPIEnums.DSGETDCNAME_FLAGS.DS_FORCE_REDISCOVERY |
                       NetAPIEnums.DSGETDCNAME_FLAGS.DS_RETURN_DNS_NAME |
                       NetAPIEnums.DSGETDCNAME_FLAGS.DS_DIRECTORY_SERVICE_REQUIRED));

            if (apiResult.IsFailed)
            {
                _dcInfoCache.TryAdd(domainName.ToUpper().Trim(), null);
                return false;
            }

            info = apiResult.Value;
            return true;
        }

        private async Task<LdapQuerySetupResult> SetupLdapQuery(LdapQueryParameters queryParameters)
        {
            var result = new LdapQuerySetupResult();
            var (success, connectionWrapper, message) =
                await _connectionPool.GetLdapConnection(queryParameters.DomainName, queryParameters.GlobalCatalog);
            if (!success)
            {
                result.Success = false;
                result.Message = $"Unable to create a connection: {message}";
                return result;
            }

            //This should never happen as far as I know, so just checking for safety
            if (connectionWrapper.Connection == null)
            {
                result.Success = false;
                result.Message = "Connection object is null";
                return result;
            }

            if (!CreateSearchRequest(queryParameters, connectionWrapper, out var searchRequest))
            {
                result.Success = false;
                result.Message = "Failed to create search request";
                _connectionPool.ReleaseConnection(connectionWrapper);
                return result;
            }

            result.Server = connectionWrapper.GetServer();
            result.Success = true;
            result.SearchRequest = searchRequest;
            result.ConnectionWrapper = connectionWrapper;
            return result;
        }

        private SearchRequest CreateSearchRequest(string distinguishedName, string ldapFilter,
            SearchScope searchScope,
            string[] attributes)
        {
            var searchRequest = new SearchRequest(distinguishedName, ldapFilter,
                searchScope, attributes);
            searchRequest.Controls.Add(new SearchOptionsControl(SearchOption.DomainScope));
            return searchRequest;
        }

        public async Task<(bool Success, string DomainName)> GetDomainNameFromSid(string sid)
        {
            string domainSid;
            try
            {
                domainSid = new SecurityIdentifier(sid).AccountDomainSid?.Value.ToUpper();
            }
            catch
            {
                var match = _sidRegex.Match(sid);
                domainSid = match.Success ? match.Groups[1].Value : null;
            }

            if (domainSid == null)
            {
                return (false, "");
            }

            if (Cache.GetDomainSidMapping(domainSid, out var domain))
            {
                return (true, domain);
            }

            try
            {
                var entry = new DirectoryEntry($"LDAP://<SID={domainSid}>");
                entry.RefreshCache(new[] { LDAPProperties.DistinguishedName });
                var dn = entry.GetProperty(LDAPProperties.DistinguishedName);
                if (!string.IsNullOrWhiteSpace(dn))
                {
                    Cache.AddDomainSidMapping(domainSid, Helpers.DistinguishedNameToDomain(dn));
                    return (true, Helpers.DistinguishedNameToDomain(dn));
                }
            }
            catch
            {
                //pass
            }

            if (await ConvertDomainSidToDomainNameFromLdap(sid) is (true, var domainName))
            {
                Cache.AddDomainSidMapping(domainSid, domainName);
                return (true, domainName);
            }

            using (var ctx = new PrincipalContext(ContextType.Domain))
            {
                try
                {
                    var principal = Principal.FindByIdentity(ctx, IdentityType.Sid, sid);
                    if (principal != null)
                    {
                        var dn = principal.DistinguishedName;
                        if (!string.IsNullOrWhiteSpace(dn))
                        {
                            Cache.AddDomainSidMapping(domainSid, Helpers.DistinguishedNameToDomain(dn));
                            return (true, Helpers.DistinguishedNameToDomain(dn));
                        }
                    }
                }
                catch
                {
                    //pass
                }
            }

            return (false, string.Empty);
        }

        private async Task<(bool Success, string DomainName)> ConvertDomainSidToDomainNameFromLdap(string domainSid)
        {
            if (!GetDomain(out var domain) || domain?.Name == null)
            {
                return (false, string.Empty);
            }

            var result = await Query(new LdapQueryParameters
            {
                DomainName = domain.Name,
                Attributes = new[] { LDAPProperties.DistinguishedName },
                GlobalCatalog = true,
                LDAPFilter = new LDAPFilter().AddDomains(CommonFilters.SpecificSID(domainSid)).GetFilter()
            }).DefaultIfEmpty(LdapResult<ISearchResultEntry>.Fail()).FirstOrDefaultAsync();

            if (result.IsSuccess)
            {
                return (true, Helpers.DistinguishedNameToDomain(result.Value.DistinguishedName));
            }

            result = await Query(new LdapQueryParameters
            {
                DomainName = domain.Name,
                Attributes = new[] { LDAPProperties.DistinguishedName },
                GlobalCatalog = true,
                LDAPFilter = new LDAPFilter().AddFilter("(objectclass=trusteddomain)", true)
                    .AddFilter($"(securityidentifier={Helpers.ConvertSidToHexSid(domainSid)})", true).GetFilter()
            }).DefaultIfEmpty(LdapResult<ISearchResultEntry>.Fail()).FirstOrDefaultAsync();

            if (result.IsSuccess)
            {
                return (true, Helpers.DistinguishedNameToDomain(result.Value.DistinguishedName));
            }

            result = await Query(new LdapQueryParameters
            {
                DomainName = domain.Name,
                Attributes = new[] { LDAPProperties.DistinguishedName },
                LDAPFilter = new LDAPFilter().AddFilter("(objectclass=domaindns)", true)
                    .AddFilter(CommonFilters.SpecificSID(domainSid), true).GetFilter()
            }).DefaultIfEmpty(LdapResult<ISearchResultEntry>.Fail()).FirstOrDefaultAsync();

            if (result.IsSuccess)
            {
                return (true, Helpers.DistinguishedNameToDomain(result.Value.DistinguishedName));
            }

            return (false, string.Empty);
        }

        public async Task<(bool Success, string DomainSid)> GetDomainSidFromDomainName(string domainName)
        {
            if (Cache.GetDomainSidMapping(domainName, out var domainSid)) return (true, domainSid);

            try
            {
                var entry = new DirectoryEntry($"LDAP://{domainName}");
                //Force load objectsid into the object cache
                entry.RefreshCache(new[] { "objectSid" });
                var sid = entry.GetSid();
                if (sid != null)
                {
                    Cache.AddDomainSidMapping(domainName, sid);
                    domainSid = sid;
                    return (true, domainSid);
                }
            }
            catch
            {
                //we expect this to fail sometimes
            }

            if (GetDomain(domainName, out var domainObject))
                try
                {
                    domainSid = domainObject.GetDirectoryEntry().GetSid();
                    if (domainSid != null)
                    {
                        Cache.AddDomainSidMapping(domainName, domainSid);
                        return (true, domainSid);
                    }
                }
                catch
                {
                    //we expect this to fail sometimes (not sure why, but better safe than sorry)
                }

            foreach (var name in _translateNames)
                try
                {
                    var account = new NTAccount(domainName, name);
                    var sid = (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));
                    domainSid = sid.AccountDomainSid.ToString();
                    Cache.AddDomainSidMapping(domainName, domainSid);
                    return (true, domainSid);
                }
                catch
                {
                    //We expect this to fail if the username doesn't exist in the domain
                }

            var result = await Query(new LdapQueryParameters()
            {
                DomainName = domainName,
                Attributes = new[] { LDAPProperties.ObjectSID },
                LDAPFilter = new LDAPFilter().AddFilter(CommonFilters.DomainControllers, true).GetFilter()
            }).DefaultIfEmpty(LdapResult<ISearchResultEntry>.Fail()).FirstOrDefaultAsync();

            if (result.IsSuccess)
            {
                var sid = result.Value.GetSid();
                if (!string.IsNullOrEmpty(sid))
                {
                    domainSid = new SecurityIdentifier(sid).AccountDomainSid.Value;
                    Cache.AddDomainSidMapping(domainName, domainSid);
                    return (true, domainSid);
                }
            }

            return (false, string.Empty);
        }

        /// <summary>
        ///     Attempts to get the Domain object representing the target domain. If null is specified for the domain name, gets
        ///     the user's current domain
        /// </summary>
        /// <param name="domain"></param>
        /// <param name="domainName"></param>
        /// <returns></returns>
        public bool GetDomain(string domainName, out Domain domain)
        {
            var cacheKey = domainName ?? _nullCacheKey;
            if (DomainCache.TryGetValue(cacheKey, out domain)) return true;

            try
            {
                DirectoryContext context;
                if (_ldapConfig.Username != null)
                    context = domainName != null
                        ? new DirectoryContext(DirectoryContextType.Domain, domainName, _ldapConfig.Username,
                            _ldapConfig.Password)
                        : new DirectoryContext(DirectoryContextType.Domain, _ldapConfig.Username,
                            _ldapConfig.Password);
                else
                    context = domainName != null
                        ? new DirectoryContext(DirectoryContextType.Domain, domainName)
                        : new DirectoryContext(DirectoryContextType.Domain);

                domain = Domain.GetDomain(context);
                if (domain == null) return false;
                DomainCache.TryAdd(cacheKey, domain);
                return true;
            }
            catch (Exception e)
            {
                _log.LogDebug(e, "GetDomain call failed for domain name {Name}", domainName);
                return false;
            }
        }

        public static bool GetDomain(string domainName, LDAPConfig ldapConfig, out Domain domain)
        {
            if (DomainCache.TryGetValue(domainName, out domain)) return true;

            try
            {
                DirectoryContext context;
                if (ldapConfig.Username != null)
                    context = domainName != null
                        ? new DirectoryContext(DirectoryContextType.Domain, domainName, ldapConfig.Username,
                            ldapConfig.Password)
                        : new DirectoryContext(DirectoryContextType.Domain, ldapConfig.Username,
                            ldapConfig.Password);
                else
                    context = domainName != null
                        ? new DirectoryContext(DirectoryContextType.Domain, domainName)
                        : new DirectoryContext(DirectoryContextType.Domain);

                domain = Domain.GetDomain(context);
                if (domain == null) return false;
                DomainCache.TryAdd(domainName, domain);
                return true;
            }
            catch (Exception e)
            {
                Logging.Logger.LogDebug("Static GetDomain call failed for domain {DomainName}: {Error}", domainName, e.Message);
                return false;
            }
        }

        /// <summary>
        ///     Attempts to get the Domain object representing the target domain. If null is specified for the domain name, gets
        ///     the user's current domain
        /// </summary>
        /// <param name="domain"></param>
        /// <param name="domainName"></param>
        /// <returns></returns>
        public bool GetDomain(out Domain domain)
        {
            var cacheKey = _nullCacheKey;
            if (DomainCache.TryGetValue(cacheKey, out domain)) return true;

            try
            {
                var context = _ldapConfig.Username != null
                    ? new DirectoryContext(DirectoryContextType.Domain, _ldapConfig.Username,
                        _ldapConfig.Password)
                    : new DirectoryContext(DirectoryContextType.Domain);

                domain = Domain.GetDomain(context);
                DomainCache.TryAdd(cacheKey, domain);
                return true;
            }
            catch (Exception e)
            {
                _log.LogDebug(e, "GetDomain call failed for blank domain");
                return false;
            }
        }

        public async Task<(bool Success, TypedPrincipal Principal)> ResolveAccountName(string name, string domain)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                return (false, null);
            }

            if (Cache.GetPrefixedValue(name, domain, out var id) && Cache.GetIDType(id, out var type))
                return (true, new TypedPrincipal
                {
                    ObjectIdentifier = id,
                    ObjectType = type
                });

            var result = await Query(new LdapQueryParameters()
            {
                DomainName = domain,
                Attributes = CommonProperties.TypeResolutionProps,
                LDAPFilter = $"(samaccountname={name})"
            }).DefaultIfEmpty(LdapResult<ISearchResultEntry>.Fail()).FirstOrDefaultAsync();

            if (result.IsSuccess)
            {
                type = result.Value.GetLabel();
                id = result.Value.GetObjectIdentifier();

                if (!string.IsNullOrWhiteSpace(id))
                {
                    Cache.AddPrefixedValue(name, domain, id);
                    Cache.AddType(id, type);
                }

                var (tempID, _) = await GetWellKnownPrincipalObjectIdentifier(id, domain);
                return (true, new TypedPrincipal(tempID, type));
            }

            return (false, null);
        }

        public async Task<(bool Success, string SecurityIdentifier)> ResolveHostToSid(string host, string domain)
        {
            //Remove SPN prefixes from the host name so we're working with a clean name
            var strippedHost = Helpers.StripServicePrincipalName(host).ToUpper().TrimEnd('$');
            if (string.IsNullOrEmpty(strippedHost))
            {
                return (false, string.Empty);
            }

            if (_hostResolutionMap.TryGetValue(strippedHost, out var sid)) return (true, sid);

            //Immediately start with NetWekstaGetInfo as its our most reliable indicator if successful
            var workstationInfo = await GetWorkstationInfo(strippedHost);
            if (workstationInfo.HasValue)
            {
                var tempName = workstationInfo.Value.ComputerName;
                var tempDomain = workstationInfo.Value.LanGroup;

                if (string.IsNullOrWhiteSpace(tempDomain))
                {
                    tempDomain = domain;
                }

                if (!string.IsNullOrWhiteSpace(tempName))
                {
                    tempName = $"{tempName}$".ToUpper();
                    if (await ResolveAccountName(tempName, tempDomain) is (true, var principal))
                    {
                        _hostResolutionMap.TryAdd(strippedHost, principal.ObjectIdentifier);
                        return (true, principal.ObjectIdentifier);
                    }
                }
            }

            //Try some socket magic to get the NETBIOS name
            if (RequestNETBIOSNameFromComputer(strippedHost, domain, out var netBiosName))
            {
                if (!string.IsNullOrWhiteSpace(netBiosName))
                {
                    var result = await ResolveAccountName($"{netBiosName}$", domain);
                    if (result.Success)
                    {
                        _hostResolutionMap.TryAdd(strippedHost, result.Principal.ObjectIdentifier);
                        return (true, result.Principal.ObjectIdentifier);
                    }
                }
            }

            //Start by handling non-IP address names
            if (!IPAddress.TryParse(strippedHost, out _))
            {
                //PRIMARY.TESTLAB.LOCAL
                if (strippedHost.Contains("."))
                {
                    var split = strippedHost.Split('.');
                    var name = split[0];
                    var result = await ResolveAccountName($"{name}$", domain);
                    if (result.Success)
                    {
                        _hostResolutionMap.TryAdd(strippedHost, result.Principal.ObjectIdentifier);
                        return (true, result.Principal.ObjectIdentifier);
                    }

                    var tempDomain = string.Join(".", split.Skip(1).ToArray());
                    result = await ResolveAccountName($"{name}$", tempDomain);
                    if (result.Success)
                    {
                        _hostResolutionMap.TryAdd(strippedHost, result.Principal.ObjectIdentifier);
                        return (true, result.Principal.ObjectIdentifier);
                    }
                }
                else
                {
                    //Format: WIN10 (probably a netbios name)
                    var result = await ResolveAccountName($"{strippedHost}$", domain);
                    if (result.Success)
                    {
                        _hostResolutionMap.TryAdd(strippedHost, result.Principal.ObjectIdentifier);
                        return (true, result.Principal.ObjectIdentifier);
                    }
                }
            }

            try
            {
                var resolvedHostname = (await Dns.GetHostEntryAsync(strippedHost)).HostName;
                var split = resolvedHostname.Split('.');
                var name = split[0];
                var result = await ResolveAccountName($"{name}$", domain);
                if (result.Success)
                {
                    _hostResolutionMap.TryAdd(strippedHost, result.Principal.ObjectIdentifier);
                    return (true, result.Principal.ObjectIdentifier);
                }

                var tempDomain = string.Join(".", split.Skip(1).ToArray());
                result = await ResolveAccountName($"{name}$", tempDomain);
                if (result.Success)
                {
                    _hostResolutionMap.TryAdd(strippedHost, result.Principal.ObjectIdentifier);
                    return (true, result.Principal.ObjectIdentifier);
                }
            }
            catch
            {
                //pass
            }

            return (false, "");
        }

        /// <summary>
        ///     Calls the NetWkstaGetInfo API on a hostname
        /// </summary>
        /// <param name="hostname"></param>
        /// <returns></returns>
        private async Task<NetAPIStructs.WorkstationInfo100?> GetWorkstationInfo(string hostname)
        {
            if (!await _portScanner.CheckPort(hostname))
                return null;

            var result = _nativeMethods.CallNetWkstaGetInfo(hostname);
            if (result.IsSuccess) return result.Value;

            return null;
        }

        public async Task<(bool Success, string[] Sids)> GetGlobalCatalogMatches(string name, string domain)
        {
            if (Cache.GetGCCache(name, out var matches))
            {
                return (true, matches);
            }

            var sids = new List<string>();

            await foreach (var result in Query(new LdapQueryParameters
            {
                DomainName = domain,
                Attributes = new[] { LDAPProperties.ObjectSID },
                GlobalCatalog = true,
                LDAPFilter = new LDAPFilter().AddUsers($"(samaccountname={name})").GetFilter()
            }))
            {
                if (result.IsSuccess)
                {
                    var sid = result.Value.GetSid();
                    if (!string.IsNullOrWhiteSpace(sid))
                    {
                        sids.Add(sid);
                    }
                }
                else
                {
                    return (false, Array.Empty<string>());
                }
            }

            Cache.AddGCCache(name, sids.ToArray());
            return (true, sids.ToArray());
        }

        public async Task<(bool Success, TypedPrincipal Principal)> ResolveCertTemplateByProperty(string propertyValue,
            string propertyName, string domainName)
        {
            var filter = new LDAPFilter().AddCertificateTemplates().AddFilter($"({propertyName}={propertyValue})", true);
            var result = await Query(new LdapQueryParameters
            {
                DomainName = domainName,
                Attributes = CommonProperties.TypeResolutionProps,
                SearchScope = SearchScope.OneLevel,
                NamingContext = NamingContext.Configuration,
                RelativeSearchBase = DirectoryPaths.CertTemplateLocation,
                LDAPFilter = filter.GetFilter(),
            }).DefaultIfEmpty(LdapResult<ISearchResultEntry>.Fail()).FirstOrDefaultAsync();

            if (!result.IsSuccess)
            {
                _log.LogWarning(
                    "Could not find certificate template with {PropertyName}:{PropertyValue}: {Error}",
                    propertyName, propertyName, result.Error);
                return (false, null);
            }

            var entry = result.Value;
            return (true, new TypedPrincipal(entry.GetGuid(), Label.CertTemplate));
        }

        /// <summary>
        ///     Uses a socket and a set of bytes to request the NETBIOS name from a remote computer
        /// </summary>
        /// <param name="server"></param>
        /// <param name="domain"></param>
        /// <param name="netbios"></param>
        /// <returns></returns>
        private static bool RequestNETBIOSNameFromComputer(string server, string domain, out string netbios)
        {
            var receiveBuffer = new byte[1024];
            var requestSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                //Set receive timeout to 1 second
                requestSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, 1000);
                EndPoint remoteEndpoint;

                //We need to create an endpoint to bind too. If its an IP, just use that.
                if (IPAddress.TryParse(server, out var parsedAddress))
                    remoteEndpoint = new IPEndPoint(parsedAddress, 137);
                else
                    //If its not an IP, we're going to try and resolve it from DNS
                    try
                    {
                        IPAddress address;
                        if (server.Contains("."))
                            address = Dns
                                .GetHostAddresses(server).First(x => x.AddressFamily == AddressFamily.InterNetwork);
                        else
                            address = Dns.GetHostAddresses($"{server}.{domain}")[0];

                        if (address == null)
                        {
                            netbios = null;
                            return false;
                        }

                        remoteEndpoint = new IPEndPoint(address, 137);
                    }
                    catch
                    {
                        //Failed to resolve an IP, so return null
                        netbios = null;
                        return false;
                    }

                var originEndpoint = new IPEndPoint(IPAddress.Any, 0);
                requestSocket.Bind(originEndpoint);

                try
                {
                    requestSocket.SendTo(NameRequest, remoteEndpoint);
                    var receivedByteCount = requestSocket.ReceiveFrom(receiveBuffer, ref remoteEndpoint);
                    if (receivedByteCount >= 90)
                    {
                        netbios = new ASCIIEncoding().GetString(receiveBuffer, 57, 16).Trim('\0', ' ');
                        return true;
                    }

                    netbios = null;
                    return false;
                }
                catch (SocketException)
                {
                    netbios = null;
                    return false;
                }
            }
            finally
            {
                //Make sure we close the socket if its open
                requestSocket.Close();
            }
        }

        /// <summary>
        /// Created for testing purposes
        /// </summary>
        /// <returns></returns>
        public ActiveDirectorySecurityDescriptor MakeSecurityDescriptor()
        {
            return new ActiveDirectorySecurityDescriptor(new ActiveDirectorySecurity());
        }

        public async Task<(bool Success, TypedPrincipal Principal)> ConvertLocalWellKnownPrincipal(SecurityIdentifier sid,
            string computerDomainSid, string computerDomain)
        {
            if (!WellKnownPrincipal.GetWellKnownPrincipal(sid.Value, out var common)) return (false, null);
            //The everyone and auth users principals are special and will be converted to the domain equivalent
            if (sid.Value is "S-1-1-0" or "S-1-5-11")
            {
                return await GetWellKnownPrincipal(sid.Value, computerDomain);
            }

            //Use the computer object id + the RID of the sid we looked up to create our new principal
            var principal = new TypedPrincipal
            {
                ObjectIdentifier = $"{computerDomainSid}-{sid.Rid()}",
                ObjectType = common.ObjectType switch
                {
                    Label.User => Label.LocalUser,
                    Label.Group => Label.LocalGroup,
                    _ => common.ObjectType
                }
            };

            return (true, principal);
        }

        public async Task<bool> IsDomainController(string computerObjectId, string domainName)
        {
            var resDomain = await GetDomainNameFromSid(domainName) is (false, var tempDomain) ? tempDomain : domainName;
            var filter = new LDAPFilter().AddFilter(CommonFilters.SpecificSID(computerObjectId), true)
                .AddFilter(CommonFilters.DomainControllers, true);
            var result = await Query(new LdapQueryParameters()
            {
                DomainName = resDomain,
                Attributes = CommonProperties.ObjectID,
                LDAPFilter = filter.GetFilter(),
            }).DefaultIfEmpty(null).FirstOrDefaultAsync();
            return result is { IsSuccess: true };
        }

        public async Task<(bool Success, TypedPrincipal Principal)> ResolveDistinguishedName(string distinguishedName)
        {
            if (_distinguishedNameCache.TryGetValue(distinguishedName, out var principal))
            {
                return (true, principal);
            }

            var domain = Helpers.DistinguishedNameToDomain(distinguishedName);
            var result = await Query(new LdapQueryParameters
            {
                DomainName = domain,
                Attributes = CommonProperties.TypeResolutionProps,
                SearchBase = distinguishedName,
                SearchScope = SearchScope.Base,
                LDAPFilter = new LDAPFilter().AddAllObjects().GetFilter()
            }).DefaultIfEmpty(null).FirstOrDefaultAsync();

            if (result is { IsSuccess: true })
            {
                var entry = result.Value;
                var id = entry.GetObjectIdentifier();
                if (id == null)
                {
                    return (false, default);
                }

                if (await GetWellKnownPrincipal(id, domain) is (true, var wellKnownPrincipal))
                {
                    _distinguishedNameCache.TryAdd(distinguishedName, wellKnownPrincipal);
                    return (true, wellKnownPrincipal);
                }

                var type = entry.GetLabel();
                principal = new TypedPrincipal(id, type);
                _distinguishedNameCache.TryAdd(distinguishedName, principal);
                return (true, principal);
            }

            using (var ctx = new PrincipalContext(ContextType.Domain))
            {
                try
                {
                    var lookupPrincipal = Principal.FindByIdentity(ctx, IdentityType.DistinguishedName, distinguishedName);
                    if (lookupPrincipal != null &&
                        ((DirectoryEntry)lookupPrincipal.GetUnderlyingObject()).GetTypedPrincipal(out principal))
                    {
                        return (true, principal);
                    }

                    return (false, default);
                }
                catch
                {
                    return (false, default);
                }
            }
        }

        public void AddDomainController(string domainControllerSID)
        {
            DomainControllers.TryAdd(domainControllerSID, new byte());
        }

        public async IAsyncEnumerable<OutputBase> GetWellKnownPrincipalOutput()
        {
            foreach (var wkp in SeenWellKnownPrincipals)
            {
                WellKnownPrincipal.GetWellKnownPrincipal(wkp.Value.WkpId, out var principal);
                OutputBase output = principal.ObjectType switch
                {
                    Label.User => new User(),
                    Label.Computer => new Computer(),
                    Label.Group => new OutputTypes.Group(),
                    Label.GPO => new GPO(),
                    Label.Domain => new OutputTypes.Domain(),
                    Label.OU => new OU(),
                    Label.Container => new Container(),
                    Label.Configuration => new Container(),
                    _ => throw new ArgumentOutOfRangeException()
                };

                output.Properties.Add("name", $"{principal.ObjectIdentifier}@{wkp.Value.DomainName}".ToUpper());
                if (await GetDomainSidFromDomainName(wkp.Value.DomainName) is (true, var sid))
                {
                    output.Properties.Add("domainsid", sid);
                }

                output.Properties.Add("domain", wkp.Value.DomainName.ToUpper());
                output.ObjectIdentifier = wkp.Key;
                yield return output;
            }
        }

        public void SetLdapConfig(LDAPConfig config)
        {
            _ldapConfig = config;
            _connectionPool.Dispose();
            _connectionPool = new ConnectionPoolManager(_ldapConfig, scanner: _portScanner);
        }

        public Task<(bool Success, string Message)> TestLdapConnection(string domain)
        {
            return _connectionPool.TestDomainConnection(domain, false);
        }

        public async Task<(bool Success, string Path)> GetNamingContextPath(string domain, NamingContext context)
        {
            if (await _connectionPool.GetLdapConnection(domain, false) is (true, var wrapper, _))
            {
                _connectionPool.ReleaseConnection(wrapper);
                if (wrapper.GetSearchBase(context, out var searchBase))
                {
                    return (true, searchBase);
                }
            }

            var property = context switch
            {
                NamingContext.Default => LDAPProperties.DefaultNamingContext,
                NamingContext.Configuration => LDAPProperties.ConfigurationNamingContext,
                NamingContext.Schema => LDAPProperties.SchemaNamingContext,
                _ => throw new ArgumentOutOfRangeException(nameof(context), context, null)
            };

            try
            {
                var entry = CreateDirectoryEntry($"LDAP://{domain}/RootDSE");
                entry.RefreshCache(new[] { property });
                var searchBase = entry.GetProperty(property);
                if (!string.IsNullOrWhiteSpace(searchBase))
                {
                    return (true, searchBase);
                }
            }
            catch
            {
                //pass
            }

            if (GetDomain(domain, out var domainObj))
            {
                try
                {
                    var entry = domainObj.GetDirectoryEntry();
                    entry.RefreshCache(new[] { property });
                    var searchBase = entry.GetProperty(property);
                    if (!string.IsNullOrWhiteSpace(searchBase))
                    {
                        return (true, searchBase);
                    }
                }
                catch
                {
                    //pass
                }

                var name = domainObj.Name;
                if (!string.IsNullOrWhiteSpace(name))
                {
                    var tempPath = Helpers.DomainNameToDistinguishedName(name);

                    var searchBase = context switch
                    {
                        NamingContext.Configuration => $"CN=Configuration,{tempPath}",
                        NamingContext.Schema => $"CN=Schema,CN=Configuration,{tempPath}",
                        NamingContext.Default => tempPath,
                        _ => throw new ArgumentOutOfRangeException()
                    };

                    return (true, searchBase);
                }
            }

            return (false, default);
        }

        private DirectoryEntry CreateDirectoryEntry(string path)
        {
            if (_ldapConfig.Username != null)
            {
                return new DirectoryEntry(path, _ldapConfig.Username, _ldapConfig.Password);
            }

            return new DirectoryEntry(path);
        }
        public void Dispose()
        {
            _connectionPool?.Dispose();
        }

        internal static bool ResolveLabel(string objectIdentifier, string distinguishedName, string samAccountType, string[] objectClasses, int flags, out Label type)
        {
            type = Label.Base;
            if (objectIdentifier != null && WellKnownPrincipal.GetWellKnownPrincipal(objectIdentifier, out var principal))
            {
                type = principal.ObjectType;
                return true;
            }

            //Override GMSA/MSA account to treat them as users for the graph
            if (objectClasses != null && (objectClasses.Contains(MSAClass, StringComparer.OrdinalIgnoreCase) ||
                                          objectClasses.Contains(GMSAClass, StringComparer.OrdinalIgnoreCase)))
            {
                type = Label.User;
                return true;
            }

            if (samAccountType != null)
            {
                var objectType = Helpers.SamAccountTypeToType(samAccountType);
                if (objectType != Label.Base)
                {
                    type = objectType;
                    return true;
                }
            }

            if (objectClasses == null)
            {
                type = Label.Base;
                return false;
            }

            if (objectClasses.Contains(GroupPolicyContainerClass, StringComparer.InvariantCultureIgnoreCase))
                type = Label.GPO;
            else if (objectClasses.Contains(OrganizationalUnitClass, StringComparer.InvariantCultureIgnoreCase))
                type = Label.OU;
            else if (objectClasses.Contains(DomainClass, StringComparer.InvariantCultureIgnoreCase))
                type = Label.Domain;
            else if (objectClasses.Contains(ContainerClass, StringComparer.InvariantCultureIgnoreCase))
                type = Label.Container;
            else if (objectClasses.Contains(ConfigurationClass, StringComparer.InvariantCultureIgnoreCase))
                type = Label.Configuration;
            else if (objectClasses.Contains(PKICertificateTemplateClass, StringComparer.InvariantCultureIgnoreCase))
                type = Label.CertTemplate;
            else if (objectClasses.Contains(PKIEnrollmentServiceClass, StringComparer.InvariantCultureIgnoreCase))
                type = Label.EnterpriseCA;
            else if (objectClasses.Contains(CertificationAuthorityClass, StringComparer.InvariantCultureIgnoreCase))
            {
                if (distinguishedName.Contains(DirectoryPaths.RootCALocation))
                    type = Label.RootCA;
                if (distinguishedName.Contains(DirectoryPaths.AIACALocation))
                    type = Label.AIACA;
                if (distinguishedName.Contains(DirectoryPaths.NTAuthStoreLocation))
                    type = Label.NTAuthStore;
            }
            else if (objectClasses.Contains(OIDContainerClass, StringComparer.InvariantCultureIgnoreCase))
            {
                if (distinguishedName.StartsWith(DirectoryPaths.OIDContainerLocation,
                        StringComparison.InvariantCultureIgnoreCase))
                    type = Label.Container;
                if (flags == 2)
                {
                    type = Label.IssuancePolicy;
                }
            }

            return type != Label.Base;
        }

        private class QueryResult
        {
            public bool Success { get; set; }
            public SearchResponse Response { get; set; }
            public string ErrorMessage { get; set; }
            public int ErrorCode { get; set; }
        }

        private const string GroupPolicyContainerClass = "groupPolicyContainer";
        private const string OrganizationalUnitClass = "organizationalUnit";
        private const string DomainClass = "domain";
        private const string ContainerClass = "container";
        private const string ConfigurationClass = "configuration";
        private const string PKICertificateTemplateClass = "pKICertificateTemplate";
        private const string PKIEnrollmentServiceClass = "pKIEnrollmentService";
        private const string CertificationAuthorityClass = "certificationAuthority";
        private const string OIDContainerClass = "msPKI-Enterprise-Oid";
        private const string GMSAClass = "msds-groupmanagedserviceaccount";
        private const string MSAClass = "msds-managedserviceaccount";
    }
}