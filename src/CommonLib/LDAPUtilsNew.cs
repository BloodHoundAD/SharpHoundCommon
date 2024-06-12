using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Runtime.CompilerServices;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.Exceptions;
using SharpHoundCommonLib.LDAPQueries;
using SharpHoundCommonLib.Processors;
using SharpHoundRPC.NetAPINative;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;
using SecurityMasks = System.DirectoryServices.Protocols.SecurityMasks;

namespace SharpHoundCommonLib;

public class LDAPUtilsNew {
    //This cache is indexed by domain sid
    private readonly ConcurrentDictionary<string, NetAPIStructs.DomainControllerInfo?> _dcInfoCache = new();
    private readonly DCConnectionCache _ldapConnectionCache = new();
    private readonly ConcurrentDictionary<string, Domain> _domainCache = new();
    private readonly ILogger _log;
    private readonly NativeMethods _nativeMethods;
    private readonly string _nullCacheKey = Guid.NewGuid().ToString();
    private readonly PortScanner _portScanner;
    private readonly string[] _translateNames = { "Administrator", "admin" };
    private readonly LDAPConfig _ldapConfig = new();

    private static readonly TimeSpan MinBackoffDelay = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan MaxBackoffDelay = TimeSpan.FromSeconds(20);
    private const int BackoffDelayMultiplier = 2;
    private const int MaxRetries = 3;
    private readonly object _lockObj = new();
    private readonly ManualResetEvent _connectionResetEvent = new(false);

    public async IAsyncEnumerable<LdapResult<ISearchResultEntry>> PagedQuery(LdapQueryParameters queryParameters,
        [EnumeratorCancellation] CancellationToken cancellationToken = new()) {
        //Always force create a new connection
        var (success, connectionWrapper, message) = await GetLdapConnection(queryParameters.DomainName,
            queryParameters.GlobalCatalog, true);
        if (!success) {
            _log.LogDebug("PagedQuery failure: unable to create a connection: {Reason}\n{Info}", message,
                queryParameters.GetQueryInfo());
            yield return new LdapResult<ISearchResultEntry> {
                Error = $"Unable to create a connection: {message}",
                QueryInfo = queryParameters.GetQueryInfo()
            };
            yield break;
        }

        //This should never happen as far as I know, so just checking for safety
        if (connectionWrapper == null) {
            _log.LogError("PagedQuery failure: ldap connection is null\n{Info}", queryParameters.GetQueryInfo());
            yield return new LdapResult<ISearchResultEntry> {
                Error = "Connection is null",
                QueryInfo = queryParameters.GetQueryInfo()
            };
            yield break;
        }

        //Pull the server name from the connection for retry logic later
        if (!connectionWrapper.GetServer(out var serverName)) {
            _log.LogDebug("PagedQuery: Failed to get server value");
            serverName = null;
        }

        if (!CreateSearchRequest(queryParameters, ref connectionWrapper, out var searchRequest)) {
            _log.LogError("PagedQuery failure: unable to resolve search base\n{Info}", queryParameters.GetQueryInfo());
            yield return new LdapResult<ISearchResultEntry> {
                Error = "Unable to create search request",
                QueryInfo = queryParameters.GetQueryInfo()
            };
            yield break;
        }

        var pageControl = new PageResultRequestControl(500);
        searchRequest.Controls.Add(pageControl);

        PageResultResponseControl pageResponse = null;
        var busyRetryCount = 0;
        LdapResult<ISearchResultEntry> tempResult = null;

        while (true) {
            if (cancellationToken.IsCancellationRequested) {
                yield break;
            }

            if (tempResult != null) {
                yield return tempResult;
                yield break;
            }

            SearchResponse response;
            try {
                _log.LogTrace("Sending paged ldap request - {Info}", queryParameters.GetQueryInfo());
                response = (SearchResponse)connectionWrapper.Connection.SendRequest(searchRequest);
                if (response != null) {
                    pageResponse = (PageResultResponseControl)response.Controls
                        .Where(x => x is PageResultResponseControl).DefaultIfEmpty(null).FirstOrDefault();
                }
            }
            catch (LdapException le) when (le.ErrorCode == (int)LdapErrorCodes.ServerDown) {
                /*
                 * If we dont have a servername, we're not going to be able to re-establish a connection here. Page cookies are only valid for the server they were generated on. Bail out.
                 */
                if (serverName == null) {
                    _log.LogError(
                        "PagedQuery - Received server down exception without a known servername. Unable to generate new connection\n{Info}",
                        queryParameters.GetQueryInfo());
                    yield break;
                }

                /*
                 * Paged queries will not use the cached ldap connections, as the intention is to only have 1 or a couple of these queries running at once.
                 * The connection logic here is simplified accordingly
                 */
                for (var retryCount = 0; retryCount < MaxRetries; retryCount++) {
                    var backoffDelay = GetNextBackoff(retryCount);
                    await Task.Delay(backoffDelay, cancellationToken);
                    if (GetLdapConnectionForServer(serverName, out var newConnectionWrapper,
                            queryParameters.GlobalCatalog,
                            true)) {
                        newConnectionWrapper.CopyContexts(connectionWrapper);
                        connectionWrapper.Connection.Dispose();
                        connectionWrapper = newConnectionWrapper;
                        _log.LogDebug(
                            "PagedQuery - Successfully created new ldap connection to {Server} after ServerDown",
                            serverName);
                        break;
                    }

                    if (retryCount == MaxRetries - 1) {
                        _log.LogError("PagedQuery - Failed to get a new connection after ServerDown.\n{Info}",
                            queryParameters.GetQueryInfo());
                        yield break;
                    }
                }
            }
            catch (LdapException le) when (le.ErrorCode == (int)ResultCode.Busy && busyRetryCount < MaxRetries) {
                /*
                 * If we get a busy error, we want to do an exponential backoff, but maintain the current connection
                 * The expectation is that given enough time, the server should stop being busy and service our query appropriately
                 */
                busyRetryCount++;
                var backoffDelay = GetNextBackoff(busyRetryCount);
                await Task.Delay(backoffDelay, cancellationToken);
            }
            catch (LdapException le) {
                //No point in printing local exceptions because they're literally worthless
                tempResult = new LdapResult<ISearchResultEntry>() {
                    Error =
                        $"PagedQuery - Caught unrecoverable exception: {le.Message} (ServerMessage: {le.ServerErrorMessage}) (ErrorCode: {le.ErrorCode})",
                    QueryInfo = queryParameters.GetQueryInfo()
                };
            }
        }
    }
    
    private static TimeSpan GetNextBackoff(int retryCount)
    {
        return TimeSpan.FromSeconds(Math.Min(
            MinBackoffDelay.TotalSeconds * Math.Pow(BackoffDelayMultiplier, retryCount),
            MaxBackoffDelay.TotalSeconds));
    }

    private bool CreateSearchRequest(LdapQueryParameters queryParameters,
        ref LdapConnectionWrapperNew connectionWrapper, out SearchRequest searchRequest) {
        string basePath;
        if (!string.IsNullOrWhiteSpace(queryParameters.SearchBase)) {
            basePath = queryParameters.SearchBase;
        }
        else if (!connectionWrapper.GetSearchBase(queryParameters.NamingContext, out basePath)) {
            string tempPath;
            if (CallDsGetDcName(queryParameters.DomainName, out var info) && info != null) {
                tempPath = DomainNameToDistinguishedName(info.Value.DomainName);
                connectionWrapper.SaveContext(queryParameters.NamingContext, basePath);
            }
            else if (GetDomain(queryParameters.DomainName, out var domainObject)) {
                tempPath = DomainNameToDistinguishedName(domainObject.Name);
            }
            else {
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

    private static string DomainNameToDistinguishedName(string domainName) {
        return $"DC={domainName.Replace(".", ",DC=")}";
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

    private bool
        GetLdapConnectionForServer(string serverName, out LdapConnectionWrapperNew connectionWrapper,
            bool globalCatalog = false, bool forceCreateNewConnection = false) {
        if (string.IsNullOrWhiteSpace(serverName)) {
            throw new ArgumentNullException(nameof(serverName));
        }

        try {
            if (!forceCreateNewConnection &&
                GetCachedConnection(serverName, globalCatalog, out connectionWrapper))
                return true;

            if (CreateLdapConnection(serverName, globalCatalog, out connectionWrapper)) {
                return true;
            }

            connectionWrapper = null;
            return false;
        }
        catch (LdapAuthenticationException e) {
            _log.LogError("Error connecting to {Domain}: credentials are invalid (error code {ErrorCode})", serverName,
                e.LdapException.ErrorCode);
            connectionWrapper = null;
            return false;
        }
        catch (NoLdapDataException) {
            _log.LogError("No data returned for domain {Domain} during initial LDAP test.", serverName);
            connectionWrapper = null;
            return false;
        }
    }

    private async Task<(bool Success, LdapConnectionWrapperNew Connection, string Message )> GetLdapConnection(
        string domainName, bool globalCatalog = false,
        bool forceCreateNewConnection = false) {
        //TODO: Pull out individual strategies into single functions for readability and better logging
        if (string.IsNullOrWhiteSpace(domainName)) throw new ArgumentNullException(nameof(domainName));

        try {
            /*
             * If a server is explicitly set on the config, we should only test this config
             */
            LdapConnectionWrapperNew connectionWrapper;
            if (_ldapConfig.Server != null) {
                _log.LogWarning("Server is overridden via config, creating connection to {Server}", _ldapConfig.Server);
                if (!forceCreateNewConnection &&
                    GetCachedConnection(domainName, globalCatalog, out connectionWrapper))
                    return (true, connectionWrapper, "");

                if (CreateLdapConnection(_ldapConfig.Server, globalCatalog, out var serverConnection)) {
                    connectionWrapper = CheckCacheConnection(serverConnection, domainName, globalCatalog,
                        forceCreateNewConnection);
                    return (true, connectionWrapper, "");
                }

                return (false, null, "Failed to connect to specified server");
            }

            if (!forceCreateNewConnection && GetCachedConnection(domainName, globalCatalog, out connectionWrapper))
                return (true, connectionWrapper, "");

            _log.LogInformation("No cached connection found for domain {Domain}, attempting a new connection",
                domainName);

            if (CreateLdapConnection(domainName.ToUpper().Trim(), globalCatalog, out connectionWrapper)) {
                _log.LogDebug("Successfully created ldap connection for domain: {Domain} using strategy 1", domainName);
                connectionWrapper =
                    CheckCacheConnection(connectionWrapper, domainName, globalCatalog, forceCreateNewConnection);
                return (true, connectionWrapper, "");
            }

            string tempDomainName;

            var dsGetDcNameResult = _nativeMethods.CallDsGetDcName(null, domainName,
                (uint)(NetAPIEnums.DSGETDCNAME_FLAGS.DS_FORCE_REDISCOVERY |
                       NetAPIEnums.DSGETDCNAME_FLAGS.DS_RETURN_DNS_NAME |
                       NetAPIEnums.DSGETDCNAME_FLAGS.DS_DIRECTORY_SERVICE_REQUIRED));
            if (dsGetDcNameResult.IsSuccess) {
                tempDomainName = dsGetDcNameResult.Value.DomainName;
                if (!forceCreateNewConnection &&
                    GetCachedConnection(tempDomainName, globalCatalog, out connectionWrapper))
                    return (true, connectionWrapper, "");

                if (!tempDomainName.Equals(domainName, StringComparison.OrdinalIgnoreCase) &&
                    CreateLdapConnection(tempDomainName, globalCatalog, out connectionWrapper)) {
                    _log.LogDebug(
                        "Successfully created ldap connection for domain: {Domain} using strategy 2 with name {NewName}",
                        domainName, tempDomainName);
                    connectionWrapper = CheckCacheConnection(connectionWrapper, tempDomainName, globalCatalog,
                        forceCreateNewConnection);
                    return (true, connectionWrapper, "");
                }

                var server = dsGetDcNameResult.Value.DomainControllerName.TrimStart('\\');

                var result =
                    await CreateLDAPConnectionWithPortCheck(server, globalCatalog);
                if (result.success) {
                    _log.LogDebug(
                        "Successfully created ldap connection for domain: {Domain} using strategy 3 to server {Server}",
                        domainName, server);
                    connectionWrapper = CheckCacheConnection(result.connection, tempDomainName, globalCatalog,
                        forceCreateNewConnection);
                    return (true, connectionWrapper, "");
                }
            }

            if (!GetDomain(domainName, out var domainObject) || domainObject.Name == null) {
                //If we don't get a result here, we effectively have no other ways to resolve this domain, so we'll just have to exit out
                _log.LogDebug(
                    "Could not get domain object from GetDomain, unable to create ldap connection for domain {Domain}",
                    domainName);
                return (false, null, "Unable to get domain object for further methods");
            }

            tempDomainName = domainObject.Name.ToUpper().Trim();
            if (!forceCreateNewConnection &&
                GetCachedConnection(tempDomainName, globalCatalog, out connectionWrapper))
                return (true, connectionWrapper, "");

            if (!tempDomainName.Equals(domainName, StringComparison.OrdinalIgnoreCase) &&
                CreateLdapConnection(tempDomainName, globalCatalog, out connectionWrapper)) {
                _log.LogDebug(
                    "Successfully created ldap connection for domain: {Domain} using strategy 4 with name {NewName}",
                    domainName, tempDomainName);
                connectionWrapper =
                    CheckCacheConnection(connectionWrapper, tempDomainName, globalCatalog, forceCreateNewConnection);
                return (true, connectionWrapper, "");
            }

            var primaryDomainController = domainObject.PdcRoleOwner.Name;
            var portConnectionResult =
                await CreateLDAPConnectionWithPortCheck(primaryDomainController, globalCatalog);
            if (portConnectionResult.success) {
                _log.LogDebug(
                    "Successfully created ldap connection for domain: {Domain} using strategy 5 with to pdc {Server}",
                    domainName, primaryDomainController);
                connectionWrapper = CheckCacheConnection(portConnectionResult.connection, tempDomainName, globalCatalog,
                    forceCreateNewConnection);
                return (true, connectionWrapper, "");
            }

            //Loop over all other domain controllers and see if we can make a good connection to any
            foreach (DomainController dc in domainObject.DomainControllers) {
                portConnectionResult =
                    await CreateLDAPConnectionWithPortCheck(primaryDomainController, globalCatalog);
                if (portConnectionResult.success) {
                    _log.LogDebug(
                        "Successfully created ldap connection for domain: {Domain} using strategy 6 with to pdc {Server}",
                        domainName, primaryDomainController);
                    connectionWrapper = CheckCacheConnection(portConnectionResult.connection, tempDomainName,
                        globalCatalog,
                        forceCreateNewConnection);
                    return (true, connectionWrapper, "");
                }
            }

            _log.LogWarning("Exhausted all potential methods of creating ldap connection to {DomainName}", domainName);
            return (false, null, "All attempted connections failed");
        }
        catch (LdapAuthenticationException e) {
            _log.LogError("Error connecting to {Domain}: credentials are invalid (error code {ErrorCode})", domainName,
                e.LdapException.ErrorCode);
            return (false, null, "Invalid credentials for connection");
        }
        catch (NoLdapDataException) {
            _log.LogError("No data returned for domain {Domain} during initial LDAP test.", domainName);
            return (false, null, "No data returned from ldap connection");
        }
    }

    private async Task<(bool success, LdapConnectionWrapperNew connection)> CreateLDAPConnectionWithPortCheck(string target, bool globalCatalog) {
        if (globalCatalog) {
            if (await _portScanner.CheckPort(target, _ldapConfig.GetGCPort(true)) || (!_ldapConfig.ForceSSL &&
                    await _portScanner.CheckPort(target, _ldapConfig.GetGCPort(false))))
                return (CreateLdapConnection(target, true, out var connection), connection);
        }
        else {
            if (await _portScanner.CheckPort(target, _ldapConfig.GetPort(true)) || (!_ldapConfig.ForceSSL &&
                    await _portScanner.CheckPort(target, _ldapConfig.GetPort(false))))
                return (CreateLdapConnection(target, true, out var connection), connection);
        }

        return (false, null);
    }

    private LdapConnectionWrapperNew CheckCacheConnection(LdapConnectionWrapperNew connectionWrapper, string domainName, bool globalCatalog, bool forceCreateNewConnection)
    {
        string cacheIdentifier;
        if (_ldapConfig.Server != null)
        {
            cacheIdentifier = _ldapConfig.Server;
        }
        else
        {
            if (!GetDomainSidFromDomainName(domainName, out cacheIdentifier))
            {
                //This is kinda gross, but its another way to get the correct domain sid
                if (!connectionWrapper.Connection.GetNamingContextSearchBase(NamingContext.Default, out var searchBase) || !GetDomainSidFromConnection(connectionWrapper.Connection, searchBase, out cacheIdentifier))
                {
                    /*
                     * If we get here, we couldn't resolve a domain sid, which is hella bad, but we also want to keep from creating a shitton of new connections
                     * Cache using the domainname and pray it all works out
                     */
                    cacheIdentifier = domainName;
                }
            }
        }
        
        if (forceCreateNewConnection)
        {
            return _ldapConnectionCache.AddOrUpdate(cacheIdentifier, globalCatalog, connectionWrapper);
        }

        return _ldapConnectionCache.TryAdd(cacheIdentifier, globalCatalog, connectionWrapper);
    }
    
    private bool GetCachedConnection(string domain, bool globalCatalog, out LdapConnectionWrapperNew connection)
    {
        //If server is set via our config, we'll always just use this as the cache key
        if (_ldapConfig.Server != null)
        {
            return _ldapConnectionCache.TryGet(_ldapConfig.Server, globalCatalog, out connection);
        }
        
        if (GetDomainSidFromDomainName(domain, out var domainSid))
        {
            if (_ldapConnectionCache.TryGet(domainSid, globalCatalog, out connection))
            {
                return true;
            }
        }

        return _ldapConnectionCache.TryGet(domain, globalCatalog, out connection);
    }

    private bool GetDomainSidFromConnection(LdapConnection connection, string searchBase, out string domainSid) {
        try {
            //This ldap filter searches for domain controllers
            //Searches for any accounts with a UAC value inclusive of 8192 bitwise
            //8192 is the flag for SERVER_TRUST_ACCOUNT, which is set only on Domain Controllers
            var searchRequest = new SearchRequest(searchBase,
                "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
                SearchScope.Subtree, "objectsid");

            var response = (SearchResponse)connection.SendRequest(searchRequest);
            if (response == null || response.Entries.Count == 0) {
                domainSid = "";
                return false;
            }

            var entry = response.Entries[0];
            var sid = entry.GetSid();
            domainSid = sid.Substring(0, sid.LastIndexOf('-')).ToUpper();
            return true;
        }
        catch (LdapException) {
            _log.LogWarning("Failed grabbing domainsid from ldap for {domain}", searchBase);
            domainSid = "";
            return false;
        }
    }

    private bool GetServerFromConnection(LdapConnection connection, out string server) {
        var searchRequest = new SearchRequest("", new LDAPFilter().AddAllObjects().GetFilter(),
            SearchScope.Base, null);
        searchRequest.Controls.Add(new SearchOptionsControl(SearchOption.DomainScope));

        var response = (SearchResponse)connection.SendRequest(searchRequest);
        if (response?.Entries == null || response.Entries.Count == 0) {
            server = "";
            return false;
        }

        var entry = response.Entries[0];
        server = entry.GetProperty(LDAPProperties.DNSHostName);
        return server != null;
    }

    private bool CreateLdapConnection(string target, bool globalCatalog,
        out LdapConnectionWrapperNew connection) {
        var baseConnection = CreateBaseConnection(target, true, globalCatalog);
        if (TestLdapConnection(baseConnection, target, out var entry)) {
            connection = new LdapConnectionWrapperNew(baseConnection, entry);
            return true;
        }

        try {
            baseConnection.Dispose();
        }
        catch {
            //this is just in case
        }

        if (_ldapConfig.ForceSSL) {
            connection = null;
            return false;
        }

        baseConnection = CreateBaseConnection(target, false, globalCatalog);
        if (TestLdapConnection(baseConnection, target, out entry)) {
            connection = new LdapConnectionWrapperNew(baseConnection, entry);
            return true;
        }

        try {
            baseConnection.Dispose();
        }
        catch {
            //this is just in case
        }

        connection = null;
        return false;
    }

    private LdapConnection CreateBaseConnection(string directoryIdentifier, bool ssl,
        bool globalCatalog) {
        var port = globalCatalog ? _ldapConfig.GetGCPort(ssl) : _ldapConfig.GetPort(ssl);
        var identifier = new LdapDirectoryIdentifier(directoryIdentifier, port, false, false);
        var connection = new LdapConnection(identifier) { Timeout = new TimeSpan(0, 0, 5, 0) };

        //These options are important!
        connection.SessionOptions.ProtocolVersion = 3;
        //Referral chasing does not work with paged searches 
        connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
        if (ssl) connection.SessionOptions.SecureSocketLayer = true;

        if (_ldapConfig.DisableSigning) {
            connection.SessionOptions.Sealing = false;
            connection.SessionOptions.Signing = false;
        }

        if (_ldapConfig.DisableCertVerification)
            connection.SessionOptions.VerifyServerCertificate = (_, _) => true;

        if (_ldapConfig.Username != null) {
            var cred = new NetworkCredential(_ldapConfig.Username, _ldapConfig.Password);
            connection.Credential = cred;
        }

        connection.AuthType = _ldapConfig.AuthType;

        return connection;
    }

    /// <summary>
    ///     Tests whether an LDAP connection is working
    /// </summary>
    /// <param name="connection"></param>
    /// <param name="identifier"></param>
    /// <param name="entry">The rootdse object for this connection if successful</param>
    /// <returns></returns>
    /// <exception cref="LdapAuthenticationException">Something is wrong with the supplied credentials</exception>
    /// <exception cref="NoLdapDataException">
    ///     A connection "succeeded" but no data was returned. This can be related to
    ///     kerberos auth across trusts or just simply lack of permissions
    /// </exception>
    private bool TestLdapConnection(LdapConnection connection, string identifier, out ISearchResultEntry entry) {
        try {
            //Attempt an initial bind. If this fails, likely auth is invalid, or its not a valid target
            connection.Bind();
        }
        catch (LdapException e) {
            //TODO: Maybe look at this and find a better way?
            if (e.ErrorCode is (int)LdapErrorCodes.InvalidCredentials or (int)ResultCode.InappropriateAuthentication) {
                connection.Dispose();
                throw new LdapAuthenticationException(e);
            }

            entry = null;
            return false;
        }
        catch (Exception e) {
            entry = null;
            return false;
        }

        SearchResponse response;
        try {
            //Do an initial search request to get the rootDSE
            //This ldap filter is equivalent to (objectclass=*)
            var searchRequest = CreateSearchRequest("", new LDAPFilter().AddAllObjects().GetFilter(),
                SearchScope.Base, null);

            response = (SearchResponse)connection.SendRequest(searchRequest);
        }
        catch (LdapException e) {
            /*
             * If we can't send the initial search request, its unlikely any other search requests will work so we will immediately return false
             */
            _log.LogDebug(e, "TestLdapConnection failed during search request against target {Target}", identifier);
            entry = null;
            return false;
        }

        if (response?.Entries == null || response.Entries.Count == 0) {
            /*
             * This can happen for one of two reasons, either we dont have permission to query AD or we're authenticating
             * across external trusts with kerberos authentication without Forest Search Order properly configured.
             * Either way, this connection isn't useful for us because we're not going to get data, so return false
             */

            _log.LogDebug("TestLdapConnection failed to return results against target {Target}", identifier);
            connection.Dispose();
            throw new NoLdapDataException();
        }

        entry = new SearchResultEntryWrapper(response.Entries[0]);
        return true;
    }

    private SearchRequest CreateSearchRequest(string distinguishedName, string ldapFilter, SearchScope searchScope,
        string[] attributes) {
        var searchRequest = new SearchRequest(distinguishedName, ldapFilter,
            searchScope, attributes);
        searchRequest.Controls.Add(new SearchOptionsControl(SearchOption.DomainScope));
        return searchRequest;
    }

    public bool GetDomainSidFromDomainName(string domainName, out string domainSid) {
        if (Cache.GetDomainSidMapping(domainName, out domainSid)) return true;

        try {
            var entry = new DirectoryEntry($"LDAP://{domainName}");
            //Force load objectsid into the object cache
            entry.RefreshCache(new[] { "objectSid" });
            var sid = entry.GetSid();
            if (sid != null) {
                Cache.AddDomainSidMapping(domainName, sid);
                domainSid = sid;
                return true;
            }
        }
        catch {
            //we expect this to fail sometimes
        }

        if (GetDomain(domainName, out var domainObject))
            try {
                domainSid = domainObject.GetDirectoryEntry().GetSid();
                if (domainSid != null) {
                    Cache.AddDomainSidMapping(domainName, domainSid);
                    return true;
                }
            }
            catch {
                //we expect this to fail sometimes (not sure why, but better safe than sorry)
            }

        foreach (var name in _translateNames)
            try {
                var account = new NTAccount(domainName, name);
                var sid = (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));
                domainSid = sid.AccountDomainSid.ToString();
                Cache.AddDomainSidMapping(domainName, domainSid);
                return true;
            }
            catch {
                //We expect this to fail if the username doesn't exist in the domain
            }

        return false;
    }

    private string ResolveDomainCrossRef(string domainName) {
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
        if (_domainCache.TryGetValue(cacheKey, out domain)) return true;

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
            _domainCache.TryAdd(cacheKey, domain);
            return true;
        }
        catch (Exception e) {
            _log.LogDebug(e, "GetDomain call failed for domain name {Name}", domainName);
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
        if (_domainCache.TryGetValue(cacheKey, out domain)) return true;

        try {
            var context = _ldapConfig.Username != null
                ? new DirectoryContext(DirectoryContextType.Domain, _ldapConfig.Username,
                    _ldapConfig.Password)
                : new DirectoryContext(DirectoryContextType.Domain);

            domain = Domain.GetDomain(context);
            _domainCache.TryAdd(cacheKey, domain);
            return true;
        }
        catch (Exception e) {
            _log.LogDebug(e, "GetDomain call failed for blank domain");
            return false;
        }
    }

    private struct LdapFailure {
        public LdapFailureReason FailureReason { get; set; }
        public string Message { get; set; }
    }
}