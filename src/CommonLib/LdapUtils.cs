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
using SharpHoundCommonLib.DirectoryObjects;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.LDAPQueries;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.Processors;
using SharpHoundRPC.NetAPINative;
using Domain = System.DirectoryServices.ActiveDirectory.Domain;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;
using SecurityMasks = System.DirectoryServices.Protocols.SecurityMasks;

namespace SharpHoundCommonLib {
    public class LdapUtils : ILdapUtils {
        //This cache is indexed by domain sid
        private readonly ConcurrentDictionary<string, NetAPIStructs.DomainControllerInfo?> _dcInfoCache = new();
        private static readonly ConcurrentDictionary<string, Domain> DomainCache = new();
        private static readonly ConcurrentDictionary<string, byte> DomainControllers = new();

        private static readonly ConcurrentDictionary<string, string> DomainToForestCache =
            new(StringComparer.OrdinalIgnoreCase);

        private static readonly ConcurrentDictionary<string, ResolvedWellKnownPrincipal>
            SeenWellKnownPrincipals = new();

        private readonly ConcurrentDictionary<string, string>
            _hostResolutionMap = new(StringComparer.OrdinalIgnoreCase);

        private readonly ConcurrentDictionary<string, TypedPrincipal> _distinguishedNameCache =
            new(StringComparer.OrdinalIgnoreCase);

        private readonly ILogger _log;
        private readonly PortScanner _portScanner;
        private readonly NativeMethods _nativeMethods;
        private readonly string _nullCacheKey = Guid.NewGuid().ToString();
        private static readonly Regex SIDRegex = new(@"^(S-\d+-\d+-\d+-\d+-\d+-\d+)(-\d+)?$");

        private readonly string[] _translateNames = { "Administrator", "admin" };
        private LdapConfig _ldapConfig = new();

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

        private class ResolvedWellKnownPrincipal {
            public string DomainName { get; set; }
            public string WkpId { get; set; }
        }

        public LdapUtils() {
            _nativeMethods = new NativeMethods();
            _portScanner = new PortScanner();
            _log = Logging.LogProvider.CreateLogger("LDAPUtils");
            _connectionPool = new ConnectionPoolManager(_ldapConfig, _log);
        }

        public LdapUtils(NativeMethods nativeMethods = null, PortScanner scanner = null, ILogger log = null) {
            _nativeMethods = nativeMethods ?? new NativeMethods();
            _portScanner = scanner ?? new PortScanner();
            _log = log ?? Logging.LogProvider.CreateLogger("LDAPUtils");
            _connectionPool = new ConnectionPoolManager(_ldapConfig, scanner: _portScanner);
        }

        public async IAsyncEnumerable<Result<string>> RangedRetrieval(string distinguishedName,
            string attributeName, [EnumeratorCancellation] CancellationToken cancellationToken = new()) {
            var domain = Helpers.DistinguishedNameToDomain(distinguishedName);

            var connectionResult = await _connectionPool.GetLdapConnection(domain, false);
            if (!connectionResult.Success) {
                yield return Result<string>.Fail(connectionResult.Message);
                yield break;
            }

            var index = 0;
            var step = 0;

            //Start by using * as our upper index, which will automatically give us the range size
            var currentRange = $"{attributeName};range={index}-*";
            var complete = false;

            var queryParameters = new LdapQueryParameters {
                DomainName = domain,
                LDAPFilter = $"{attributeName}=*",
                Attributes = new[] { currentRange },
                SearchScope = SearchScope.Base,
                SearchBase = distinguishedName
            };
            var connectionWrapper = connectionResult.ConnectionWrapper;

            if (!CreateSearchRequest(queryParameters, connectionWrapper, out var searchRequest)) {
                _connectionPool.ReleaseConnection(connectionWrapper);
                yield return Result<string>.Fail("Failed to create search request");
                yield break;
            }

            var queryRetryCount = 0;
            var busyRetryCount = 0;

            LdapResult<string> tempResult = null;

            while (!cancellationToken.IsCancellationRequested) {
                SearchResponse response = null;
                try {
                    response = (SearchResponse)connectionWrapper.Connection.SendRequest(searchRequest);
                } catch (LdapException le) when (le.ErrorCode == (int)ResultCode.Busy && busyRetryCount < MaxRetries) {
                    busyRetryCount++;
                    var backoffDelay = GetNextBackoff(busyRetryCount);
                    await Task.Delay(backoffDelay, cancellationToken);
                } catch (LdapException le) when (le.ErrorCode == (int)LdapErrorCodes.ServerDown &&
                                                 queryRetryCount < MaxRetries) {
                    queryRetryCount++;
                    _connectionPool.ReleaseConnection(connectionWrapper, true);
                    for (var retryCount = 0; retryCount < MaxRetries; retryCount++) {
                        var backoffDelay = GetNextBackoff(retryCount);
                        await Task.Delay(backoffDelay, cancellationToken);
                        var (success, newConnectionWrapper, message) =
                            await _connectionPool.GetLdapConnection(domain,
                                false);
                        if (success) {
                            _log.LogDebug(
                                "RangedRetrieval - Recovered from ServerDown successfully, connection made to {NewServer}",
                                newConnectionWrapper.GetServer());
                            connectionWrapper = newConnectionWrapper;
                            break;
                        }

                        //If we hit our max retries for making a new connection, set tempResult so we can yield it after this logic
                        if (retryCount == MaxRetries - 1) {
                            _log.LogError(
                                "RangedRetrieval - Failed to get a new connection after ServerDown for path {Path}",
                                distinguishedName);
                            tempResult =
                                LdapResult<string>.Fail(
                                    "RangedRetrieval - Failed to get a new connection after ServerDown.",
                                    queryParameters, le.ErrorCode);
                        }
                    }
                } catch (LdapException le) {
                    tempResult = LdapResult<string>.Fail(
                        $"Caught unrecoverable ldap exception: {le.Message} (ServerMessage: {le.ServerErrorMessage}) (ErrorCode: {le.ErrorCode})",
                        queryParameters, le.ErrorCode);
                } catch (Exception e) {
                    tempResult =
                        LdapResult<string>.Fail($"Caught unrecoverable exception: {e.Message}", queryParameters);
                }

                //If we have a tempResult set it means we hit an error we couldn't recover from, so yield that result and then break out of the function
                //We handle connection release in the relevant exception blocks
                if (tempResult != null) {
                    if (tempResult.ErrorCode == (int)LdapErrorCodes.ServerDown) {
                        _connectionPool.ReleaseConnection(connectionWrapper, true);
                    } else {
                        _connectionPool.ReleaseConnection(connectionWrapper);
                    }

                    yield return tempResult;
                    yield break;
                }

                if (response?.Entries.Count == 1) {
                    var entry = response.Entries[0];
                    //We dont know the name of our attribute, but there should only be one, so we're safe to just use a loop here
                    foreach (string attr in entry.Attributes.AttributeNames) {
                        currentRange = attr;
                        complete = currentRange.IndexOf("*", 0, StringComparison.OrdinalIgnoreCase) > 0;
                        step = entry.Attributes[currentRange].Count;
                    }

                    foreach (string dn in entry.Attributes[currentRange].GetValues(typeof(string))) {
                        yield return Result<string>.Ok(dn);
                        index++;
                    }

                    if (complete) {
                        _connectionPool.ReleaseConnection(connectionWrapper);
                        yield break;
                    }

                    currentRange = $"{attributeName};range={index}-{index + step}";
                    searchRequest.Attributes.Clear();
                    searchRequest.Attributes.Add(currentRange);
                } else {
                    //I dont know what can cause a RR to have multiple entries, but its nothing good. Break out
                    _connectionPool.ReleaseConnection(connectionWrapper);
                    yield break;
                }
            }

            _connectionPool.ReleaseConnection(connectionWrapper);
        }

        public async IAsyncEnumerable<LdapResult<IDirectoryObject>> Query(LdapQueryParameters queryParameters,
            [EnumeratorCancellation] CancellationToken cancellationToken = new()) {
            var setupResult = await SetupLdapQuery(queryParameters);

            if (!setupResult.Success) {
                _log.LogInformation("Query - Failure during query setup: {Reason}\n{Info}", setupResult.Message,
                    queryParameters.GetQueryInfo());
                yield break;
            }

            var searchRequest = setupResult.SearchRequest;
            var connectionWrapper = setupResult.ConnectionWrapper;

            if (cancellationToken.IsCancellationRequested) {
                _connectionPool.ReleaseConnection(connectionWrapper);
                yield break;
            }

            var queryRetryCount = 0;
            var busyRetryCount = 0;
            LdapResult<IDirectoryObject> tempResult = null;
            var querySuccess = false;
            SearchResponse response = null;
            while (!cancellationToken.IsCancellationRequested) {
                try {
                    _log.LogTrace("Sending ldap request - {Info}", queryParameters.GetQueryInfo());
                    response = (SearchResponse)connectionWrapper.Connection.SendRequest(searchRequest);

                    if (response != null) {
                        querySuccess = true;
                    } else if (queryRetryCount == MaxRetries) {
                        tempResult =
                            LdapResult<IDirectoryObject>.Fail($"Failed to get a response after {MaxRetries} attempts",
                                queryParameters);
                    } else {
                        queryRetryCount++;
                        continue;
                    }
                } catch (LdapException le) when (le.ErrorCode == (int)LdapErrorCodes.ServerDown &&
                                                 queryRetryCount < MaxRetries) {
                    /*
                     * A ServerDown exception indicates that our connection is no longer valid for one of many reasons.
                     * We'll want to release our connection back to the pool, but dispose it. We need a new connection,
                     * and because this is not a paged query, we can get this connection from anywhere.
                     */

                    //Increment our query retry count
                    queryRetryCount++;
                    _connectionPool.ReleaseConnection(connectionWrapper, true);

                    for (var retryCount = 0; retryCount < MaxRetries; retryCount++) {
                        var backoffDelay = GetNextBackoff(retryCount);
                        await Task.Delay(backoffDelay, cancellationToken);
                        var (success, newConnectionWrapper, message) =
                            await _connectionPool.GetLdapConnection(queryParameters.DomainName,
                                queryParameters.GlobalCatalog);
                        if (success) {
                            _log.LogDebug(
                                "Query - Recovered from ServerDown successfully, connection made to {NewServer}",
                                newConnectionWrapper.GetServer());
                            connectionWrapper = newConnectionWrapper;
                            break;
                        }

                        //If we hit our max retries for making a new connection, set tempResult so we can yield it after this logic
                        if (retryCount == MaxRetries - 1) {
                            _log.LogError("Query - Failed to get a new connection after ServerDown.\n{Info}",
                                queryParameters.GetQueryInfo());
                            tempResult =
                                LdapResult<IDirectoryObject>.Fail(
                                    "Query - Failed to get a new connection after ServerDown.", queryParameters);
                        }
                    }
                } catch (LdapException le) when (le.ErrorCode == (int)ResultCode.Busy && busyRetryCount < MaxRetries) {
                    /*
                     * If we get a busy error, we want to do an exponential backoff, but maintain the current connection
                     * The expectation is that given enough time, the server should stop being busy and service our query appropriately
                     */
                    busyRetryCount++;
                    var backoffDelay = GetNextBackoff(busyRetryCount);
                    await Task.Delay(backoffDelay, cancellationToken);
                } catch (LdapException le) {
                    tempResult = LdapResult<IDirectoryObject>.Fail(
                        $"Query - Caught unrecoverable ldap exception: {le.Message} (ServerMessage: {le.ServerErrorMessage}) (ErrorCode: {le.ErrorCode})",
                        queryParameters);
                } catch (Exception e) {
                    tempResult =
                        LdapResult<IDirectoryObject>.Fail($"Query - Caught unrecoverable exception: {e.Message}",
                            queryParameters);
                }

                //If we have a tempResult set it means we hit an error we couldn't recover from, so yield that result and then break out of the function
                if (tempResult != null) {
                    if (tempResult.ErrorCode == (int)LdapErrorCodes.ServerDown) {
                        _connectionPool.ReleaseConnection(connectionWrapper, true);
                    } else {
                        _connectionPool.ReleaseConnection(connectionWrapper);
                    }

                    yield return tempResult;
                    yield break;
                }

                //If we've successfully made our query, break out of the while loop
                if (querySuccess) {
                    break;
                }
            }

            _connectionPool.ReleaseConnection(connectionWrapper);
            foreach (SearchResultEntry entry in response.Entries) {
                yield return LdapResult<IDirectoryObject>.Ok(new SearchResultEntryWrapper(entry));
            }
        }

        public async IAsyncEnumerable<LdapResult<IDirectoryObject>> PagedQuery(LdapQueryParameters queryParameters,
            [EnumeratorCancellation] CancellationToken cancellationToken = new()) {
            var setupResult = await SetupLdapQuery(queryParameters);

            if (!setupResult.Success) {
                _log.LogInformation("PagedQuery - Failure during query setup: {Reason}\n{Info}", setupResult.Message,
                    queryParameters.GetQueryInfo());
                yield break;
            }

            var searchRequest = setupResult.SearchRequest;
            var connectionWrapper = setupResult.ConnectionWrapper;
            var serverName = setupResult.Server;

            if (serverName == null) {
                _log.LogWarning("PagedQuery - Failed to get a server name for connection, retry not possible");
            }

            var pageControl = new PageResultRequestControl(500);
            searchRequest.Controls.Add(pageControl);

            PageResultResponseControl pageResponse = null;
            var busyRetryCount = 0;
            var queryRetryCount = 0;
            LdapResult<IDirectoryObject> tempResult = null;

            while (!cancellationToken.IsCancellationRequested) {
                SearchResponse response = null;
                try {
                    _log.LogTrace("Sending paged ldap request - {Info}", queryParameters.GetQueryInfo());
                    response = (SearchResponse)connectionWrapper.Connection.SendRequest(searchRequest);
                    if (response != null) {
                        pageResponse = (PageResultResponseControl)response.Controls
                            .Where(x => x is PageResultResponseControl).DefaultIfEmpty(null).FirstOrDefault();
                        queryRetryCount = 0;
                    } else if (queryRetryCount == MaxRetries) {
                        tempResult = LdapResult<IDirectoryObject>.Fail(
                            $"PagedQuery - Failed to get a response after {MaxRetries} attempts",
                            queryParameters);
                    } else {
                        queryRetryCount++;
                    }
                } catch (LdapException le) when (le.ErrorCode == (int)LdapErrorCodes.ServerDown) {
                    /*
                     * If we dont have a servername, we're not going to be able to re-establish a connection here. Page cookies are only valid for the server they were generated on. Bail out.
                     */
                    if (serverName == null) {
                        _log.LogError(
                            "PagedQuery - Received server down exception without a known servername. Unable to generate new connection\n{Info}",
                            queryParameters.GetQueryInfo());
                        _connectionPool.ReleaseConnection(connectionWrapper, true);
                        yield break;
                    }

                    /*
                     * Paged queries will not use the cached ldap connections, as the intention is to only have 1 or a couple of these queries running at once.
                     * The connection logic here is simplified accordingly
                     */
                    _connectionPool.ReleaseConnection(connectionWrapper, true);
                    for (var retryCount = 0; retryCount < MaxRetries; retryCount++) {
                        var backoffDelay = GetNextBackoff(retryCount);
                        await Task.Delay(backoffDelay, cancellationToken);
                        var (success, ldapConnectionWrapperNew, message) =
                            await _connectionPool.GetLdapConnectionForServer(
                                queryParameters.DomainName, serverName, queryParameters.GlobalCatalog);

                        if (success) {
                            _log.LogDebug("PagedQuery - Recovered from ServerDown successfully");
                            connectionWrapper = ldapConnectionWrapperNew;
                            break;
                        }

                        if (retryCount == MaxRetries - 1) {
                            _log.LogError("PagedQuery - Failed to get a new connection after ServerDown.\n{Info}",
                                queryParameters.GetQueryInfo());
                            tempResult =
                                LdapResult<IDirectoryObject>.Fail("Failed to get a new connection after serverdown",
                                    queryParameters, le.ErrorCode);
                        }
                    }
                } catch (LdapException le) when (le.ErrorCode == (int)ResultCode.Busy && busyRetryCount < MaxRetries) {
                    /*
                     * If we get a busy error, we want to do an exponential backoff, but maintain the current connection
                     * The expectation is that given enough time, the server should stop being busy and service our query appropriately
                     */
                    busyRetryCount++;
                    var backoffDelay = GetNextBackoff(busyRetryCount);
                    await Task.Delay(backoffDelay, cancellationToken);
                } catch (LdapException le) {
                    tempResult = LdapResult<IDirectoryObject>.Fail(
                        $"PagedQuery - Caught unrecoverable ldap exception: {le.Message} (ServerMessage: {le.ServerErrorMessage}) (ErrorCode: {le.ErrorCode})",
                        queryParameters, le.ErrorCode);
                } catch (Exception e) {
                    tempResult =
                        LdapResult<IDirectoryObject>.Fail($"PagedQuery - Caught unrecoverable exception: {e.Message}",
                            queryParameters);
                }

                if (tempResult != null) {
                    if (tempResult.ErrorCode == (int)LdapErrorCodes.ServerDown) {
                        _connectionPool.ReleaseConnection(connectionWrapper, true);
                    } else {
                        _connectionPool.ReleaseConnection(connectionWrapper);
                    }

                    yield return tempResult;
                    yield break;
                }

                if (cancellationToken.IsCancellationRequested) {
                    _connectionPool.ReleaseConnection(connectionWrapper);
                    yield break;
                }

                //I'm not sure why this happens sometimes, but if we try the request again, it works sometimes, other times we get an exception
                if (response == null || pageResponse == null) {
                    continue;
                }

                foreach (SearchResultEntry entry in response.Entries) {
                    if (cancellationToken.IsCancellationRequested) {
                        _connectionPool.ReleaseConnection(connectionWrapper);
                        yield break;
                    }

                    yield return LdapResult<IDirectoryObject>.Ok(new SearchResultEntryWrapper(entry));
                }

                if (pageResponse.Cookie.Length == 0 || response.Entries.Count == 0 ||
                    cancellationToken.IsCancellationRequested) {
                    _connectionPool.ReleaseConnection(connectionWrapper);
                    yield break;
                }

                pageControl.Cookie = pageResponse.Cookie;
            }
        }

        public async Task<(bool Success, TypedPrincipal Principal)> ResolveIDAndType(
            SecurityIdentifier securityIdentifier,
            string objectDomain) {
            return await ResolveIDAndType(securityIdentifier.Value, objectDomain);
        }

        public async Task<(bool Success, TypedPrincipal Principal)>
            ResolveIDAndType(string identifier, string objectDomain) {
            if (identifier.Contains("0ACNF")) {
                return (false, new TypedPrincipal(identifier, Label.Base));
            }

            if (await GetWellKnownPrincipal(identifier, objectDomain) is (true, var principal)) {
                return (true, principal);
            }

            if (identifier.StartsWith("S-")) {
                var result = await LookupSidType(identifier, objectDomain);
                return (result.Success, new TypedPrincipal(identifier, result.Type));
            }

            var (success, type) = await LookupGuidType(identifier, objectDomain);
            return (success, new TypedPrincipal(identifier, type));
        }

        private async Task<(bool Success, Label Type)> LookupSidType(string sid, string domain) {
            if (Cache.GetIDType(sid, out var type)) {
                return (true, type);
            }

            var tempDomain = domain;

            if (await GetDomainNameFromSid(sid) is (true, var domainName)) {
                tempDomain = domainName;
            }

            var result = await Query(new LdapQueryParameters() {
                DomainName = tempDomain,
                LDAPFilter = CommonFilters.SpecificSID(sid),
                Attributes = CommonProperties.TypeResolutionProps
            }).DefaultIfEmpty(LdapResult<IDirectoryObject>.Fail()).FirstOrDefaultAsync();

            if (result.IsSuccess) {
                if (result.Value.GetLabel(out type)) {
                    Cache.AddType(sid, type);
                    return (true, type);
                }
            }

            try {
                var entry = CreateDirectoryEntry($"LDAP://<SID={sid}>");
                if (entry.GetLabel(out type)) {
                    Cache.AddType(sid, type);
                    return (true, type);
                }
            } catch {
                //pass
            }

            using (var ctx = new PrincipalContext(ContextType.Domain)) {
                try {
                    var principal = Principal.FindByIdentity(ctx, IdentityType.Sid, sid);
                    if (principal != null) {
                        var entry = ((DirectoryEntry)principal.GetUnderlyingObject()).ToDirectoryObject();
                        if (entry.GetLabel(out type)) {
                            Cache.AddType(sid, type);
                            return (true, type);
                        }
                    }
                } catch {
                    //pass
                }
            }

            return (false, Label.Base);
        }

        private async Task<(bool Success, Label type)> LookupGuidType(string guid, string domain) {
            if (Cache.GetIDType(guid, out var type)) {
                return (true, type);
            }

            var result = await Query(new LdapQueryParameters() {
                DomainName = domain,
                LDAPFilter = CommonFilters.SpecificGUID(guid),
                Attributes = CommonProperties.TypeResolutionProps
            }).DefaultIfEmpty(LdapResult<IDirectoryObject>.Fail()).FirstOrDefaultAsync();

            if (result.IsSuccess && result.Value.GetLabel(out type)) {
                Cache.AddType(guid, type);
                return (true, type);
            }

            try {
                var entry = CreateDirectoryEntry($"LDAP://<GUID={guid}>");
                if (entry.GetLabel(out type)) {
                    Cache.AddType(guid, type);
                    return (true, type);
                }
            } catch {
                //pass
            }

            using (var ctx = new PrincipalContext(ContextType.Domain)) {
                try {
                    var principal = Principal.FindByIdentity(ctx, IdentityType.Guid, guid);
                    if (principal != null) {
                        var entry = ((DirectoryEntry)principal.GetUnderlyingObject()).ToDirectoryObject();
                        if (entry.GetLabel(out type)) {
                            Cache.AddType(guid, type);
                            return (true, type);
                        }
                    }
                } catch {
                    //pass
                }
            }

            return (false, Label.Base);
        }

        public async Task<(bool Success, TypedPrincipal WellKnownPrincipal)> GetWellKnownPrincipal(
            string securityIdentifier, string objectDomain) {
            if (!WellKnownPrincipal.GetWellKnownPrincipal(securityIdentifier, out var wellKnownPrincipal)) {
                return (false, null);
            }

            var (newIdentifier, newDomain) =
                await GetWellKnownPrincipalObjectIdentifier(securityIdentifier, objectDomain);

            wellKnownPrincipal.ObjectIdentifier = newIdentifier;
            SeenWellKnownPrincipals.TryAdd(wellKnownPrincipal.ObjectIdentifier, new ResolvedWellKnownPrincipal {
                DomainName = newDomain,
                WkpId = securityIdentifier
            });

            return (true, wellKnownPrincipal);
        }

        private async Task<(string ObjectID, string Domain)> GetWellKnownPrincipalObjectIdentifier(
            string securityIdentifier, string domain) {
            if (!WellKnownPrincipal.GetWellKnownPrincipal(securityIdentifier, out _))
                return (securityIdentifier, string.Empty);

            if (!securityIdentifier.Equals("S-1-5-9", StringComparison.OrdinalIgnoreCase)) {
                var tempDomain = domain;
                if (GetDomain(tempDomain, out var domainObject) && domainObject.Name != null) {
                    tempDomain = domainObject.Name;
                }

                return ($"{tempDomain}-{securityIdentifier}".ToUpper(), tempDomain);
            }

            if (await GetForest(domain) is (true, var forest)) {
                return ($"{forest}-{securityIdentifier}".ToUpper(), forest);
            }

            _log.LogWarning("Failed to get a forest name for domain {Domain}, unable to resolve enterprise DC sid",
                domain);
            return ($"UNKNOWN-{securityIdentifier}", "UNKNOWN");
        }

        public virtual async Task<(bool Success, string ForestName)> GetForest(string domain) {
            if (DomainToForestCache.TryGetValue(domain, out var cachedForest)) {
                return (true, cachedForest);
            }

            if (GetDomain(domain, out var domainObject)) {
                try {
                    var forestName = domainObject.Forest.Name.ToUpper();
                    DomainToForestCache.TryAdd(domain, forestName);
                    return (true, forestName);
                } catch {
                    //pass
                }
            }

            var (success, forest) = await GetForestFromLdap(domain);
            if (success) {
                DomainToForestCache.TryAdd(domain, forest);
                return (true, forest);
            }

            return (false, null);
        }

        private async Task<(bool Success, string ForestName)> GetForestFromLdap(string domain) {
            var queryParameters = new LdapQueryParameters {
                Attributes = new[] { LDAPProperties.RootDomainNamingContext },
                SearchScope = SearchScope.Base,
                DomainName = domain,
                LDAPFilter = new LdapFilter().AddAllObjects().GetFilter(),
            };

            var result = await Query(queryParameters).DefaultIfEmpty(LdapResult<IDirectoryObject>.Fail()).FirstOrDefaultAsync();
            if (result.IsSuccess &&
                result.Value.TryGetProperty(LDAPProperties.RootDomainNamingContext, out var rootNamingContext)) {
                return (true, Helpers.DistinguishedNameToDomain(rootNamingContext).ToUpper());
            }

            return (false, null);
        }

        private static TimeSpan GetNextBackoff(int retryCount) {
            return TimeSpan.FromSeconds(Math.Min(
                MinBackoffDelay.TotalSeconds * Math.Pow(BackoffDelayMultiplier, retryCount),
                MaxBackoffDelay.TotalSeconds));
        }

        private bool CreateSearchRequest(LdapQueryParameters queryParameters,
            LdapConnectionWrapper connectionWrapper, out SearchRequest searchRequest) {
            string basePath;
            if (!string.IsNullOrWhiteSpace(queryParameters.SearchBase)) {
                basePath = queryParameters.SearchBase;
            } else if (!connectionWrapper.GetSearchBase(queryParameters.NamingContext, out basePath)) {
                string tempPath;
                if (CallDsGetDcName(queryParameters.DomainName, out var info) && info != null) {
                    tempPath = Helpers.DomainNameToDistinguishedName(info.Value.DomainName);
                    connectionWrapper.SaveContext(queryParameters.NamingContext, basePath);
                } else if (GetDomain(queryParameters.DomainName, out var domainObject)) {
                    tempPath = Helpers.DomainNameToDistinguishedName(domainObject.Name);
                } else {
                    searchRequest = null;
                    return false;
                }

                basePath = queryParameters.NamingContext switch {
                    NamingContext.Configuration => $"CN=Configuration,{tempPath}",
                    NamingContext.Schema => $"CN=Schema,CN=Configuration,{tempPath}",
                    NamingContext.Default => tempPath,
                    _ => throw new ArgumentOutOfRangeException()
                };

                connectionWrapper.SaveContext(queryParameters.NamingContext, basePath);

                if (!string.IsNullOrWhiteSpace(queryParameters.RelativeSearchBase)) {
                    basePath = $"{queryParameters.RelativeSearchBase},{basePath}";
                }
            }

            searchRequest = new SearchRequest(basePath, queryParameters.LDAPFilter, queryParameters.SearchScope,
                queryParameters.Attributes);
            searchRequest.Controls.Add(new SearchOptionsControl(SearchOption.DomainScope));
            if (queryParameters.IncludeDeleted) {
                searchRequest.Controls.Add(new ShowDeletedControl());
            }

            if (queryParameters.IncludeSecurityDescriptor) {
                searchRequest.Controls.Add(new SecurityDescriptorFlagControl {
                    SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner
                });
            }

            return true;
        }

        private bool CallDsGetDcName(string domainName, out NetAPIStructs.DomainControllerInfo? info) {
            if (_dcInfoCache.TryGetValue(domainName.ToUpper().Trim(), out info)) return info != null;

            var apiResult = _nativeMethods.CallDsGetDcName(null, domainName,
                (uint)(NetAPIEnums.DSGETDCNAME_FLAGS.DS_FORCE_REDISCOVERY |
                       NetAPIEnums.DSGETDCNAME_FLAGS.DS_RETURN_DNS_NAME |
                       NetAPIEnums.DSGETDCNAME_FLAGS.DS_DIRECTORY_SERVICE_REQUIRED));

            if (apiResult.IsFailed) {
                _dcInfoCache.TryAdd(domainName.ToUpper().Trim(), null);
                return false;
            }

            info = apiResult.Value;
            return true;
        }

        private async Task<LdapQuerySetupResult> SetupLdapQuery(LdapQueryParameters queryParameters) {
            var result = new LdapQuerySetupResult();
            var (success, connectionWrapper, message) =
                await _connectionPool.GetLdapConnection(queryParameters.DomainName, queryParameters.GlobalCatalog);
            if (!success) {
                result.Success = false;
                result.Message = $"Unable to create a connection: {message}";
                return result;
            }

            //This should never happen as far as I know, so just checking for safety
            if (connectionWrapper.Connection == null) {
                result.Success = false;
                result.Message = "Connection object is null";
                return result;
            }

            if (!CreateSearchRequest(queryParameters, connectionWrapper, out var searchRequest)) {
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
            string[] attributes) {
            var searchRequest = new SearchRequest(distinguishedName, ldapFilter,
                searchScope, attributes);
            searchRequest.Controls.Add(new SearchOptionsControl(SearchOption.DomainScope));
            return searchRequest;
        }

        public async Task<(bool Success, string DomainName)> GetDomainNameFromSid(string sid) {
            string domainSid;
            try {
                domainSid = new SecurityIdentifier(sid).AccountDomainSid?.Value.ToUpper();
            } catch {
                var match = SIDRegex.Match(sid);
                domainSid = match.Success ? match.Groups[1].Value : null;
            }

            if (domainSid == null) {
                return (false, "");
            }

            if (Cache.GetDomainSidMapping(domainSid, out var domain)) {
                return (true, domain);
            }

            try {
                var entry = CreateDirectoryEntry($"LDAP://<SID={domainSid}>");
                if (entry.TryGetDistinguishedName(out var dn)) {
                    Cache.AddDomainSidMapping(domainSid, Helpers.DistinguishedNameToDomain(dn));
                    return (true, Helpers.DistinguishedNameToDomain(dn));
                }
            } catch {
                //pass
            }

            if (await ConvertDomainSidToDomainNameFromLdap(sid) is (true, var domainName)) {
                Cache.AddDomainSidMapping(domainSid, domainName);
                return (true, domainName);
            }

            using (var ctx = new PrincipalContext(ContextType.Domain)) {
                try {
                    var principal = Principal.FindByIdentity(ctx, IdentityType.Sid, sid);
                    if (principal != null) {
                        var dn = principal.DistinguishedName;
                        if (!string.IsNullOrWhiteSpace(dn)) {
                            Cache.AddDomainSidMapping(domainSid, Helpers.DistinguishedNameToDomain(dn));
                            return (true, Helpers.DistinguishedNameToDomain(dn));
                        }
                    }
                } catch {
                    //pass
                }
            }

            return (false, string.Empty);
        }

        private async Task<(bool Success, string DomainName)> ConvertDomainSidToDomainNameFromLdap(string domainSid) {
            if (!GetDomain(out var domain) || domain?.Name == null) {
                return (false, string.Empty);
            }

            var result = await Query(new LdapQueryParameters {
                DomainName = domain.Name,
                Attributes = new[] { LDAPProperties.DistinguishedName },
                GlobalCatalog = true,
                LDAPFilter = new LdapFilter().AddDomains(CommonFilters.SpecificSID(domainSid)).GetFilter()
            }).DefaultIfEmpty(LdapResult<IDirectoryObject>.Fail()).FirstOrDefaultAsync();

            if (result.IsSuccess && result.Value.TryGetDistinguishedName(out var distinguishedName)) {
                return (true, Helpers.DistinguishedNameToDomain(distinguishedName));
            }

            result = await Query(new LdapQueryParameters {
                DomainName = domain.Name,
                Attributes = new[] { LDAPProperties.DistinguishedName },
                GlobalCatalog = true,
                LDAPFilter = new LdapFilter().AddFilter("(objectclass=trusteddomain)", true)
                    .AddFilter($"(securityidentifier={Helpers.ConvertSidToHexSid(domainSid)})", true).GetFilter()
            }).DefaultIfEmpty(LdapResult<IDirectoryObject>.Fail()).FirstOrDefaultAsync();

            if (result.IsSuccess && result.Value.TryGetDistinguishedName(out distinguishedName)) {
                return (true, Helpers.DistinguishedNameToDomain(distinguishedName));
            }

            result = await Query(new LdapQueryParameters {
                DomainName = domain.Name,
                Attributes = new[] { LDAPProperties.DistinguishedName },
                LDAPFilter = new LdapFilter().AddFilter("(objectclass=domaindns)", true)
                    .AddFilter(CommonFilters.SpecificSID(domainSid), true).GetFilter()
            }).DefaultIfEmpty(LdapResult<IDirectoryObject>.Fail()).FirstOrDefaultAsync();

            if (result.IsSuccess && result.Value.TryGetDistinguishedName(out distinguishedName)) {
                return (true, Helpers.DistinguishedNameToDomain(distinguishedName));
            }

            return (false, string.Empty);
        }

        public async Task<(bool Success, string DomainSid)> GetDomainSidFromDomainName(string domainName) {
            if (Cache.GetDomainSidMapping(domainName, out var domainSid)) return (true, domainSid);

            try {
                var entry = CreateDirectoryEntry($"LDAP://{domainName}");
                //Force load objectsid into the object cache
                if (entry.TryGetSecurityIdentifier(out var sid)) {
                    Cache.AddDomainSidMapping(domainName, sid);
                    domainSid = sid;
                    return (true, domainSid);
                }
            } catch {
                //we expect this to fail sometimes
            }

            if (GetDomain(domainName, out var domainObject))
                try {
                    var entry = domainObject.GetDirectoryEntry().ToDirectoryObject();
                    if (entry.TryGetSecurityIdentifier(out domainSid)) {
                        Cache.AddDomainSidMapping(domainName, domainSid);
                        return (true, domainSid);
                    }
                } catch {
                    //we expect this to fail sometimes (not sure why, but better safe than sorry)
                }

            foreach (var name in _translateNames)
                try {
                    var account = new NTAccount(domainName, name);
                    var sid = (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));
                    domainSid = sid.AccountDomainSid.ToString();
                    Cache.AddDomainSidMapping(domainName, domainSid);
                    return (true, domainSid);
                } catch {
                    //We expect this to fail if the username doesn't exist in the domain
                }

            var result = await Query(new LdapQueryParameters() {
                DomainName = domainName,
                Attributes = new[] { LDAPProperties.ObjectSID },
                LDAPFilter = new LdapFilter().AddFilter(CommonFilters.DomainControllers, true).GetFilter()
            }).DefaultIfEmpty(LdapResult<IDirectoryObject>.Fail()).FirstOrDefaultAsync();

            if (result.IsSuccess && result.Value.TryGetSecurityIdentifier(out var securityIdentifier)) {
                domainSid = new SecurityIdentifier(securityIdentifier).AccountDomainSid.Value;
                Cache.AddDomainSidMapping(domainName, domainSid);
                return (true, domainSid);
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
        public bool GetDomain(string domainName, out Domain domain) {
            var cacheKey = domainName ?? _nullCacheKey;
            if (DomainCache.TryGetValue(cacheKey, out domain)) return true;

            try {
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
            } catch (Exception e) {
                _log.LogDebug(e, "GetDomain call failed for domain name {Name}", domainName);
                return false;
            }
        }

        public static bool GetDomain(string domainName, LdapConfig ldapConfig, out Domain domain) {
            if (DomainCache.TryGetValue(domainName, out domain)) return true;

            try {
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
            } catch (Exception e) {
                Logging.Logger.LogDebug("Static GetDomain call failed for domain {DomainName}: {Error}", domainName,
                    e.Message);
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
        public bool GetDomain(out Domain domain) {
            var cacheKey = _nullCacheKey;
            if (DomainCache.TryGetValue(cacheKey, out domain)) return true;

            try {
                var context = _ldapConfig.Username != null
                    ? new DirectoryContext(DirectoryContextType.Domain, _ldapConfig.Username,
                        _ldapConfig.Password)
                    : new DirectoryContext(DirectoryContextType.Domain);

                domain = Domain.GetDomain(context);
                DomainCache.TryAdd(cacheKey, domain);
                return true;
            } catch (Exception e) {
                _log.LogDebug(e, "GetDomain call failed for blank domain");
                return false;
            }
        }

        public async Task<(bool Success, TypedPrincipal Principal)> ResolveAccountName(string name, string domain) {
            if (string.IsNullOrWhiteSpace(name)) {
                return (false, null);
            }

            if (Cache.GetPrefixedValue(name, domain, out var id) && Cache.GetIDType(id, out var type))
                return (true, new TypedPrincipal {
                    ObjectIdentifier = id,
                    ObjectType = type
                });

            var result = await Query(new LdapQueryParameters() {
                DomainName = domain,
                Attributes = CommonProperties.TypeResolutionProps,
                LDAPFilter = $"(samaccountname={name})"
            }).DefaultIfEmpty(LdapResult<IDirectoryObject>.Fail()).FirstOrDefaultAsync();

            if (result.IsSuccess && result.Value.GetObjectIdentifier(out id)) {
                result.Value.GetLabel(out type);
                Cache.AddPrefixedValue(name, domain, id);
                Cache.AddType(id, type);

                var (tempID, _) = await GetWellKnownPrincipalObjectIdentifier(id, domain);
                return (true, new TypedPrincipal(tempID, type));
            }

            return (false, null);
        }

        public async Task<(bool Success, string SecurityIdentifier)> ResolveHostToSid(string host, string domain) {
            //Remove SPN prefixes from the host name so we're working with a clean name
            var strippedHost = Helpers.StripServicePrincipalName(host).ToUpper().TrimEnd('$');
            if (string.IsNullOrEmpty(strippedHost)) {
                return (false, string.Empty);
            }

            if (_hostResolutionMap.TryGetValue(strippedHost, out var sid)) return (true, sid);

            //Immediately start with NetWkstaGetInfo as it's our most reliable indicator if successful
            if (await GetWorkstationInfo(strippedHost) is (true, var workstationInfo)) {
                var tempName = workstationInfo.ComputerName;
                var tempDomain = workstationInfo.LanGroup;

                if (string.IsNullOrWhiteSpace(tempDomain)) {
                    tempDomain = domain;
                }

                if (!string.IsNullOrWhiteSpace(tempName)) {
                    tempName = $"{tempName}$".ToUpper();
                    if (await ResolveAccountName(tempName, tempDomain) is (true, var principal)) {
                        _hostResolutionMap.TryAdd(strippedHost, principal.ObjectIdentifier);
                        return (true, principal.ObjectIdentifier);
                    }
                }
            }

            //Try some socket magic to get the NETBIOS name
            if (RequestNETBIOSNameFromComputer(strippedHost, domain, out var netBiosName)) {
                if (!string.IsNullOrWhiteSpace(netBiosName)) {
                    var result = await ResolveAccountName($"{netBiosName}$", domain);
                    if (result.Success) {
                        _hostResolutionMap.TryAdd(strippedHost, result.Principal.ObjectIdentifier);
                        return (true, result.Principal.ObjectIdentifier);
                    }
                }
            }

            //Start by handling non-IP address names
            if (!IPAddress.TryParse(strippedHost, out _)) {
                //PRIMARY.TESTLAB.LOCAL
                if (strippedHost.Contains(".")) {
                    var split = strippedHost.Split('.');
                    var name = split[0];
                    var result = await ResolveAccountName($"{name}$", domain);
                    if (result.Success) {
                        _hostResolutionMap.TryAdd(strippedHost, result.Principal.ObjectIdentifier);
                        return (true, result.Principal.ObjectIdentifier);
                    }

                    var tempDomain = string.Join(".", split.Skip(1).ToArray());
                    result = await ResolveAccountName($"{name}$", tempDomain);
                    if (result.Success) {
                        _hostResolutionMap.TryAdd(strippedHost, result.Principal.ObjectIdentifier);
                        return (true, result.Principal.ObjectIdentifier);
                    }
                } else {
                    //Format: WIN10 (probably a netbios name)
                    var result = await ResolveAccountName($"{strippedHost}$", domain);
                    if (result.Success) {
                        _hostResolutionMap.TryAdd(strippedHost, result.Principal.ObjectIdentifier);
                        return (true, result.Principal.ObjectIdentifier);
                    }
                }
            }

            try {
                var resolvedHostname = (await Dns.GetHostEntryAsync(strippedHost)).HostName;
                var split = resolvedHostname.Split('.');
                var name = split[0];
                var result = await ResolveAccountName($"{name}$", domain);
                if (result.Success) {
                    _hostResolutionMap.TryAdd(strippedHost, result.Principal.ObjectIdentifier);
                    return (true, result.Principal.ObjectIdentifier);
                }

                var tempDomain = string.Join(".", split.Skip(1).ToArray());
                result = await ResolveAccountName($"{name}$", tempDomain);
                if (result.Success) {
                    _hostResolutionMap.TryAdd(strippedHost, result.Principal.ObjectIdentifier);
                    return (true, result.Principal.ObjectIdentifier);
                }
            } catch {
                //pass
            }

            return (false, "");
        }

        /// <summary>
        ///     Calls the NetWkstaGetInfo API on a hostname
        /// </summary>
        /// <param name="hostname"></param>
        /// <returns></returns>
        private async Task<(bool Success, NetAPIStructs.WorkstationInfo100 Info)> GetWorkstationInfo(string hostname) {
            if (!await _portScanner.CheckPort(hostname))
                return (false, default);

            var result = _nativeMethods.CallNetWkstaGetInfo(hostname);
            if (result.IsSuccess) return (true, result.Value);

            return (false, default);
        }

        public async Task<(bool Success, string[] Sids)> GetGlobalCatalogMatches(string name, string domain) {
            if (Cache.GetGCCache(name, out var matches)) {
                return (true, matches);
            }

            var sids = new List<string>();

            await foreach (var result in Query(new LdapQueryParameters {
                               DomainName = domain,
                               Attributes = new[] { LDAPProperties.ObjectSID },
                               GlobalCatalog = true,
                               LDAPFilter = new LdapFilter().AddUsers($"(samaccountname={name})").GetFilter()
                           })) {
                if (result.IsSuccess && result.Value.TryGetSecurityIdentifier(out var sid)) {
                    if (await GetWellKnownPrincipal(sid, domain) is (true, var principal)) {
                        sids.Add(principal.ObjectIdentifier);
                    } else {
                        sids.Add(sid);    
                    }
                } else {
                    return (false, Array.Empty<string>());
                }
            }

            Cache.AddGCCache(name, sids.ToArray());
            return (true, sids.ToArray());
        }

        public async Task<(bool Success, TypedPrincipal Principal)> ResolveCertTemplateByProperty(string propertyValue,
            string propertyName, string domainName) {
            var filter = new LdapFilter().AddCertificateTemplates()
                .AddFilter($"({propertyName}={propertyValue})", true);
            var result = await Query(new LdapQueryParameters {
                DomainName = domainName,
                Attributes = CommonProperties.TypeResolutionProps,
                SearchScope = SearchScope.OneLevel,
                NamingContext = NamingContext.Configuration,
                RelativeSearchBase = DirectoryPaths.CertTemplateLocation,
                LDAPFilter = filter.GetFilter(),
            }).DefaultIfEmpty(LdapResult<IDirectoryObject>.Fail()).FirstOrDefaultAsync();

            if (!result.IsSuccess) {
                _log.LogWarning(
                    "Could not find certificate template with {PropertyName}:{PropertyValue}: {Error}",
                    propertyName, propertyValue, result.Error);
                return (false, null);
            }

            if (result.Value.TryGetGuid(out var guid)) {
                return (true, new TypedPrincipal(guid, Label.CertTemplate));
            }

            return (false, default);
        }

        /// <summary>
        ///     Uses a socket and a set of bytes to request the NETBIOS name from a remote computer
        /// </summary>
        /// <param name="server"></param>
        /// <param name="domain"></param>
        /// <param name="netbios"></param>
        /// <returns></returns>
        private static bool RequestNETBIOSNameFromComputer(string server, string domain, out string netbios) {
            var receiveBuffer = new byte[1024];
            var requestSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            try {
                //Set receive timeout to 1 second
                requestSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, 1000);
                EndPoint remoteEndpoint;

                //We need to create an endpoint to bind too. If its an IP, just use that.
                if (IPAddress.TryParse(server, out var parsedAddress))
                    remoteEndpoint = new IPEndPoint(parsedAddress, 137);
                else
                    //If its not an IP, we're going to try and resolve it from DNS
                    try {
                        IPAddress address;
                        if (server.Contains("."))
                            address = Dns
                                .GetHostAddresses(server).First(x => x.AddressFamily == AddressFamily.InterNetwork);
                        else
                            address = Dns.GetHostAddresses($"{server}.{domain}")[0];

                        if (address == null) {
                            netbios = null;
                            return false;
                        }

                        remoteEndpoint = new IPEndPoint(address, 137);
                    } catch {
                        //Failed to resolve an IP, so return null
                        netbios = null;
                        return false;
                    }

                var originEndpoint = new IPEndPoint(IPAddress.Any, 0);
                requestSocket.Bind(originEndpoint);

                try {
                    requestSocket.SendTo(NameRequest, remoteEndpoint);
                    var receivedByteCount = requestSocket.ReceiveFrom(receiveBuffer, ref remoteEndpoint);
                    if (receivedByteCount >= 90) {
                        netbios = new ASCIIEncoding().GetString(receiveBuffer, 57, 16).Trim('\0', ' ');
                        return true;
                    }

                    netbios = null;
                    return false;
                } catch (SocketException) {
                    netbios = null;
                    return false;
                }
            } finally {
                //Make sure we close the socket if its open
                requestSocket.Close();
            }
        }

        /// <summary>
        /// Created for testing purposes
        /// </summary>
        /// <returns></returns>
        public ActiveDirectorySecurityDescriptor MakeSecurityDescriptor() {
            return new ActiveDirectorySecurityDescriptor(new ActiveDirectorySecurity());
        }

        public async Task<(bool Success, TypedPrincipal Principal)> ConvertLocalWellKnownPrincipal(
            SecurityIdentifier sid,
            string computerDomainSid, string computerDomain) {
            if (!WellKnownPrincipal.GetWellKnownPrincipal(sid.Value, out var common)) return (false, null);
            //The "Everyone" and "Authenticated Users" principals are special and will be converted to the domain equivalent
            if (sid.Value is "S-1-1-0" or "S-1-5-11") {
                return await GetWellKnownPrincipal(sid.Value, computerDomain);
            }

            //Use the computer object id + the RID of the sid we looked up to create our new principal
            var principal = new TypedPrincipal {
                ObjectIdentifier = $"{computerDomainSid}-{sid.Rid()}",
                ObjectType = common.ObjectType switch {
                    Label.User => Label.LocalUser,
                    Label.Group => Label.LocalGroup,
                    _ => common.ObjectType
                }
            };

            return (true, principal);
        }

        public async Task<bool> IsDomainController(string computerObjectId, string domainName) {
            if (DomainControllers.ContainsKey(computerObjectId)) {
                return true;
            }
            var resDomain = await GetDomainNameFromSid(domainName) is (false, var tempDomain) ? tempDomain : domainName;
            var filter = new LdapFilter().AddFilter(CommonFilters.SpecificSID(computerObjectId), true)
                .AddFilter(CommonFilters.DomainControllers, true);
            var result = await Query(new LdapQueryParameters() {
                DomainName = resDomain,
                Attributes = CommonProperties.ObjectID,
                LDAPFilter = filter.GetFilter(),
            }).DefaultIfEmpty(LdapResult<IDirectoryObject>.Fail()).FirstOrDefaultAsync();
            if (result.IsSuccess) {
                DomainControllers.TryAdd(computerObjectId, new byte());
            }
            return result.IsSuccess;
        }

        public async Task<(bool Success, TypedPrincipal Principal)> ResolveDistinguishedName(string distinguishedName) {
            if (_distinguishedNameCache.TryGetValue(distinguishedName, out var principal)) {
                return (true, principal);
            }

            var domain = Helpers.DistinguishedNameToDomain(distinguishedName);
            var result = await Query(new LdapQueryParameters {
                DomainName = domain,
                Attributes = CommonProperties.TypeResolutionProps,
                SearchBase = distinguishedName,
                SearchScope = SearchScope.Base,
                LDAPFilter = new LdapFilter().AddAllObjects().GetFilter()
            }).DefaultIfEmpty(LdapResult<IDirectoryObject>.Fail()).FirstOrDefaultAsync();

            if (result.IsSuccess && result.Value.GetObjectIdentifier(out var id)) {
                var entry = result.Value;

                if (await GetWellKnownPrincipal(id, domain) is (true, var wellKnownPrincipal)) {
                    _distinguishedNameCache.TryAdd(distinguishedName, wellKnownPrincipal);
                    return (true, wellKnownPrincipal);
                }

                entry.GetLabel(out var type);
                principal = new TypedPrincipal(id, type);
                _distinguishedNameCache.TryAdd(distinguishedName, principal);
                return (true, principal);
            }

            using (var ctx = new PrincipalContext(ContextType.Domain)) {
                try {
                    var lookupPrincipal =
                        Principal.FindByIdentity(ctx, IdentityType.DistinguishedName, distinguishedName);
                    if (lookupPrincipal != null) {
                        var entry = ((DirectoryEntry)lookupPrincipal.GetUnderlyingObject()).ToDirectoryObject();
                        if (entry.GetObjectIdentifier(out var identifier) && entry.GetLabel(out var label)) {
                            if (await GetWellKnownPrincipal(identifier, domain) is (true, var wellKnownPrincipal)) {
                                _distinguishedNameCache.TryAdd(distinguishedName, wellKnownPrincipal);
                                return (true, wellKnownPrincipal);
                            }

                            principal = new TypedPrincipal(identifier, label);
                            _distinguishedNameCache.TryAdd(distinguishedName, principal);
                            return (true, new TypedPrincipal(identifier, label));
                        }
                    }

                    return (false, default);
                } catch {
                    return (false, default);
                }
            }
        }

        public void AddDomainController(string domainControllerSID) {
            DomainControllers.TryAdd(domainControllerSID, new byte());
        }

        public async IAsyncEnumerable<OutputBase> GetWellKnownPrincipalOutput() {
            foreach (var wkp in SeenWellKnownPrincipals) {
                WellKnownPrincipal.GetWellKnownPrincipal(wkp.Value.WkpId, out var principal);
                OutputBase output = principal.ObjectType switch {
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
                if (await GetDomainSidFromDomainName(wkp.Value.DomainName) is (true, var sid)) {
                    output.Properties.Add("domainsid", sid);
                }

                output.Properties.Add("domain", wkp.Value.DomainName.ToUpper());
                output.ObjectIdentifier = wkp.Key;
                yield return output;
            }
        }

        public void SetLdapConfig(LdapConfig config) {
            _ldapConfig = config;
            _connectionPool.Dispose();
            _connectionPool = new ConnectionPoolManager(_ldapConfig, scanner: _portScanner);
        }

        public Task<(bool Success, string Message)> TestLdapConnection(string domain) {
            return _connectionPool.TestDomainConnection(domain, false);
        }

        public async Task<(bool Success, string Path)> GetNamingContextPath(string domain, NamingContext context) {
            if (await _connectionPool.GetLdapConnection(domain, false) is (true, var wrapper, _)) {
                _connectionPool.ReleaseConnection(wrapper);
                if (wrapper.GetSearchBase(context, out var searchBase)) {
                    return (true, searchBase);
                }
            }

            var property = context switch {
                NamingContext.Default => LDAPProperties.DefaultNamingContext,
                NamingContext.Configuration => LDAPProperties.ConfigurationNamingContext,
                NamingContext.Schema => LDAPProperties.SchemaNamingContext,
                _ => throw new ArgumentOutOfRangeException(nameof(context), context, null)
            };

            try {
                var entry = CreateDirectoryEntry($"LDAP://{domain}/RootDSE");
                if (entry.TryGetProperty(property, out var searchBase)) {
                    return (true, searchBase);
                }
            } catch {
                //pass
            }

            if (GetDomain(domain, out var domainObj)) {
                try {
                    var entry = domainObj.GetDirectoryEntry().ToDirectoryObject();
                    if (entry.TryGetProperty(property, out var searchBase)) {
                        return (true, searchBase);
                    }
                } catch {
                    //pass
                }

                var name = domainObj.Name;
                if (!string.IsNullOrWhiteSpace(name)) {
                    var tempPath = Helpers.DomainNameToDistinguishedName(name);

                    var searchBase = context switch {
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

        private IDirectoryObject CreateDirectoryEntry(string path) {
            if (_ldapConfig.Username != null) {
                return new DirectoryEntry(path, _ldapConfig.Username, _ldapConfig.Password).ToDirectoryObject();
            }

            return new DirectoryEntry(path).ToDirectoryObject();
        }

        public void Dispose() {
            _connectionPool?.Dispose();
        }

        internal static bool ResolveLabel(string objectIdentifier, string distinguishedName, string samAccountType,
            string[] objectClasses, int flags, out Label type) {
            type = Label.Base;
            if (objectIdentifier != null &&
                WellKnownPrincipal.GetWellKnownPrincipal(objectIdentifier, out var principal)) {
                type = principal.ObjectType;
                return true;
            }

            //Override GMSA/MSA account to treat them as users for the graph
            if (objectClasses != null &&
                (objectClasses.Contains(ObjectClass.MSAClass, StringComparer.OrdinalIgnoreCase) ||
                 objectClasses.Contains(ObjectClass.GMSAClass, StringComparer.OrdinalIgnoreCase))) {
                type = Label.User;
                return true;
            }

            if (samAccountType != null) {
                var objectType = Helpers.SamAccountTypeToType(samAccountType);
                if (objectType != Label.Base) {
                    type = objectType;
                    return true;
                }
            }

            if (objectClasses == null || objectClasses.Length == 0) {
                type = Label.Base;
                return false;
            }

            if (objectClasses.Contains(ObjectClass.GroupPolicyContainerClass, StringComparer.OrdinalIgnoreCase))
                type = Label.GPO;
            else if (objectClasses.Contains(ObjectClass.OrganizationalUnitClass, StringComparer.OrdinalIgnoreCase))
                type = Label.OU;
            else if (objectClasses.Contains(ObjectClass.DomainClass, StringComparer.OrdinalIgnoreCase))
                type = Label.Domain;
            else if (objectClasses.Contains(ObjectClass.ContainerClass, StringComparer.OrdinalIgnoreCase))
                type = Label.Container;
            else if (objectClasses.Contains(ObjectClass.ConfigurationClass, StringComparer.OrdinalIgnoreCase))
                type = Label.Configuration;
            else if (objectClasses.Contains(ObjectClass.PKICertificateTemplateClass, StringComparer.OrdinalIgnoreCase))
                type = Label.CertTemplate;
            else if (objectClasses.Contains(ObjectClass.PKIEnrollmentServiceClass, StringComparer.OrdinalIgnoreCase))
                type = Label.EnterpriseCA;
            else if (objectClasses.Contains(ObjectClass.CertificationAuthorityClass,
                         StringComparer.OrdinalIgnoreCase)) {
                if (distinguishedName.IndexOf(DirectoryPaths.RootCALocation, StringComparison.OrdinalIgnoreCase) > 0)
                    type = Label.RootCA;
                if (distinguishedName.IndexOf(DirectoryPaths.AIACALocation, StringComparison.OrdinalIgnoreCase) > 0)
                    type = Label.AIACA;
                if (distinguishedName.IndexOf(DirectoryPaths.NTAuthStoreLocation, StringComparison.OrdinalIgnoreCase) >
                    0)
                    type = Label.NTAuthStore;
            } else if (objectClasses.Contains(ObjectClass.OIDContainerClass, StringComparer.OrdinalIgnoreCase)) {
                if (distinguishedName.StartsWith(DirectoryPaths.OIDContainerLocation,
                        StringComparison.OrdinalIgnoreCase))
                    type = Label.Container;
                else if (flags == 2) {
                    type = Label.IssuancePolicy;
                }
            }

            return type != Label.Base;
        }

        public static async Task<(bool Success, ResolvedSearchResult ResolvedResult)> ResolveSearchResult(
            IDirectoryObject directoryObject, ILdapUtils utils) {
            if (!directoryObject.GetObjectIdentifier(out var objectIdentifier)) {
                return (false, default);
            }
            
            var res = new ResolvedSearchResult {
                ObjectId = objectIdentifier
            };
            
            //If the object is deleted, we can short circuit the rest of this logic as we don't really care about anything else
            if (directoryObject.IsDeleted()) {
                res.Deleted = true;
                return (true, res);
            }

            if (directoryObject.TryGetIntProperty(LDAPProperties.UserAccountControl, out var rawUac)) {
                var flags = (UacFlags)rawUac;
                if (flags.HasFlag(UacFlags.ServerTrustAccount)) {
                    res.IsDomainController = true;
                    utils.AddDomainController(objectIdentifier);
                }
            }
            
            string domain;

            if (directoryObject.TryGetDistinguishedName(out var distinguishedName)) {
                domain = Helpers.DistinguishedNameToDomain(distinguishedName);
            } else {
                if (objectIdentifier.StartsWith("S-1-5") &&
                    await utils.GetDomainNameFromSid(objectIdentifier) is (true, var domainName)) {
                    domain = domainName;
                } else {
                    return (false, default);
                }
            }

            string domainSid;
            var match = SIDRegex.Match(objectIdentifier);
            if (match.Success) {
                domainSid = match.Groups[1].Value;
            } else if (await utils.GetDomainSidFromDomainName(domain) is (true, var sid)) {
                domainSid = sid;
            } else {
                Logging.Logger.LogWarning("Failed to resolve domain sid for object {Identifier}", objectIdentifier);
                domainSid = null;
            }

            res.Domain = domain;
            res.DomainSid = domainSid;

            if (WellKnownPrincipal.GetWellKnownPrincipal(objectIdentifier, out var wellKnownPrincipal)) {
                res.DisplayName = $"{wellKnownPrincipal.ObjectIdentifier}@{domain}";
                res.ObjectType = wellKnownPrincipal.ObjectType;
                if (await utils.GetWellKnownPrincipal(objectIdentifier, domain) is (true, var convertedPrincipal)) {
                    res.ObjectId = convertedPrincipal.ObjectIdentifier;
                }

                return (true, res);
            }

            if (!directoryObject.GetLabel(out var label)) {
                if (await utils.ResolveIDAndType(objectIdentifier, domain) is (true, var typedPrincipal)) {
                    label = typedPrincipal.ObjectType;
                }
            }

            if (directoryObject.IsMSA() || directoryObject.IsGMSA()) {
                label = Label.User;
            }

            res.ObjectType = label;

            directoryObject.TryGetProperty(LDAPProperties.SAMAccountName, out var samAccountName);

            switch (label) {
                case Label.User:
                case Label.Group:
                case Label.Base:
                    res.DisplayName = $"{samAccountName}@{domain}";
                    break;
                case Label.Computer: {
                    var shortName = samAccountName?.TrimEnd('$');
                    if (directoryObject.TryGetProperty(LDAPProperties.DNSHostName, out var dns)) {
                        res.DisplayName = dns;
                    } else if (!string.IsNullOrWhiteSpace(shortName)) {
                        res.DisplayName = $"{shortName}.{domain}";
                    } else if (directoryObject.TryGetProperty(LDAPProperties.CanonicalName,
                                   out var canonicalName)) {
                        res.DisplayName = $"{canonicalName}.{domain}";
                    } else if (directoryObject.TryGetProperty(LDAPProperties.Name, out var name)) {
                        res.DisplayName = $"{name}.{domain}";
                    } else {
                        res.DisplayName = $"UNKNOWN.{domain}";
                    }

                    break;
                }
                case Label.GPO:
                case Label.IssuancePolicy: {
                    if (directoryObject.TryGetProperty(LDAPProperties.DisplayName, out var displayName)) {
                        res.DisplayName = $"{displayName}@{domain}";
                    } else if (directoryObject.TryGetProperty(LDAPProperties.CanonicalName,
                                   out var canonicalName)) {
                        res.DisplayName = $"{canonicalName}@{domain}";
                    } else {
                        res.DisplayName = $"UNKNOWN@{domain}";
                    }

                    break;
                }
                case Label.Domain:
                    res.DisplayName = domain;
                    break;
                case Label.OU: {
                    if (directoryObject.TryGetProperty(LDAPProperties.Name, out var name)) {
                        res.DisplayName = $"{name}@{domain}";
                    } else if (directoryObject.TryGetProperty(LDAPProperties.OU, out var ou)) {
                        res.DisplayName = $"{ou}@{domain}";
                    } else {
                        res.DisplayName = $"UNKNOWN@{domain}";
                    }

                    break;
                }
                case Label.Container: {
                    if (directoryObject.TryGetProperty(LDAPProperties.Name, out var name)) {
                        res.DisplayName = $"{name}@{domain}";
                    } else if (directoryObject.TryGetProperty(LDAPProperties.CanonicalName,
                                   out var canonicalName)) {
                        res.DisplayName = $"{canonicalName}@{domain}";
                    } else {
                        res.DisplayName = $"UNKNOWN@{domain}";
                    }

                    break;
                }
                case Label.Configuration:
                case Label.RootCA:
                case Label.AIACA:
                case Label.NTAuthStore:
                case Label.EnterpriseCA:
                case Label.CertTemplate: {
                    if (directoryObject.TryGetProperty(LDAPProperties.Name, out var name)) {
                        res.DisplayName = $"{name}@{domain}";
                    } else {
                        res.DisplayName = $"UNKNOWN@{domain}";
                    }

                    break;
                }
                default:
                    throw new ArgumentOutOfRangeException();
            }

            res.DisplayName = res.DisplayName.ToUpper();
            return (true, res);
        }
    }
}