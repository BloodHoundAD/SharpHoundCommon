using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.Exceptions;
using SharpHoundCommonLib.LDAPQueries;
using SharpHoundCommonLib.Processors;
using SharpHoundRPC.NetAPINative;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;

namespace SharpHoundCommonLib;

public class LDAPUtilsNew
{
    private readonly string _nullCacheKey = Guid.NewGuid().ToString();
    private LDAPConfig _ldapConfig = new();
    private readonly ILogger _log;
    //This cache is indexed by domain sid
    private readonly ConcurrentDictionary<LDAPConnectionCacheKey, LdapConnection> _ldapConnectionCache = new();
    private readonly ConcurrentDictionary<string, Domain> _domainCache = new();
    private readonly string[] _translateNames = { "Administrator", "admin" };
    private readonly PortScanner _portScanner;
    private readonly NativeMethods _nativeMethods;
    
    public async IAsyncEnumerable<ISearchResultEntry> PagedQuery(string ldapFilter)
    {
        
    }

    private async Task<(bool, LdapConnection)> GetLdapConnection(string domainName, AuthType authType = AuthType.Negotiate, bool globalCatalog = false,
        bool forceCreateNewConnection = false)
    {
        //TODO: Pull out individual strategies into single functions for readability and better logging
        if (string.IsNullOrWhiteSpace(domainName))
        {
            throw new ArgumentNullException(nameof(domainName));
        }

        LdapConnection connection;

        try
        {
            /*
             * If a server is explicitly set on the config, we should only test this config
             */
            if (_ldapConfig.Server != null)
            {
                _log.LogWarning("Server is overridden via config, creating connection to {Server}", _ldapConfig.Server);
                if (!forceCreateNewConnection && GetCachedConnection(domainName, globalCatalog, out connection))
                {
                    return (true, connection);
                }

                if (CreateLdapConnection(_ldapConfig.Server, authType, globalCatalog, out var serverConnection))
                {
                    connection = CheckCacheConnection(serverConnection, domainName, globalCatalog,
                        forceCreateNewConnection);
                    return (true, connection);
                }
                
                return (false, null);
            }

            if (!forceCreateNewConnection && GetCachedConnection(domainName, globalCatalog, out connection))
            {
                return (true, connection);
            }

            _log.LogInformation("No cached connection found for domain {Domain}, attempting a new connection",
                domainName);

            if (CreateLdapConnection(domainName.ToUpper().Trim(), authType, globalCatalog, out connection))
            {
                _log.LogDebug("Successfully created ldap connection for domain: {Domain} using strategy 1", domainName);
                connection = CheckCacheConnection(connection, domainName, globalCatalog, forceCreateNewConnection);
                return (true, connection);
            }

            string tempDomainName;

            var dsGetDcNameResult = _nativeMethods.CallDsGetDcName(null, domainName, (uint)(NetAPIEnums.DSGETDCNAME_FLAGS.DS_FORCE_REDISCOVERY | NetAPIEnums.DSGETDCNAME_FLAGS.DS_RETURN_DNS_NAME | NetAPIEnums.DSGETDCNAME_FLAGS.DS_DIRECTORY_SERVICE_REQUIRED));
            if (dsGetDcNameResult.IsSuccess)
            {
                tempDomainName = dsGetDcNameResult.Value.DomainName;
                if (!forceCreateNewConnection && GetCachedConnection(tempDomainName, globalCatalog, out connection))
                {
                    return (true, connection);
                }
                
                if (!tempDomainName.Equals(domainName, StringComparison.OrdinalIgnoreCase) && CreateLdapConnection(tempDomainName, authType, globalCatalog, out connection))
                {
                    _log.LogDebug("Successfully created ldap connection for domain: {Domain} using strategy 2 with name {NewName}", domainName, tempDomainName);
                    connection = CheckCacheConnection(connection, tempDomainName, globalCatalog, forceCreateNewConnection);
                    return (true, connection);
                }

                var server = dsGetDcNameResult.Value.DomainControllerName.TrimStart('\\');

                var result =
                    await CreateLDAPConnectionWithPortCheck(server, authType, globalCatalog);
                if (result.success)
                {
                    _log.LogDebug("Successfully created ldap connection for domain: {Domain} using strategy 3 to server {Server}", domainName,server);
                    connection = CheckCacheConnection(result.connection, tempDomainName, globalCatalog,
                        forceCreateNewConnection);
                    return (true, connection);
                }
            }

            if (!GetDomain(domainName, out var domainObject) || domainObject.Name == null)
            {
                //If we don't get a result here, we effectively have no other ways to resolve this domain, so we'll just have to exit out
                _log.LogDebug("Could not get domain object from GetDomain, unable to create ldap connection for domain {Domain}", domainName);
                return (false, null);
            }

            tempDomainName = domainObject.Name.ToUpper().Trim();
            if (!forceCreateNewConnection && GetCachedConnection(tempDomainName, globalCatalog, out connection))
            {
                return (true, connection);
            }
            
            if (!tempDomainName.Equals(domainName, StringComparison.OrdinalIgnoreCase) && CreateLdapConnection(tempDomainName, authType, globalCatalog, out connection))
            {
                _log.LogDebug("Successfully created ldap connection for domain: {Domain} using strategy 4 with name {NewName}", domainName, tempDomainName);
                connection = CheckCacheConnection(connection, tempDomainName, globalCatalog, forceCreateNewConnection);
                return (true, connection);
            }

            var primaryDomainController = domainObject.PdcRoleOwner.Name;
            var portConnectionResult =
                await CreateLDAPConnectionWithPortCheck(primaryDomainController, authType, globalCatalog);
            if (portConnectionResult.success)
            {
                _log.LogDebug("Successfully created ldap connection for domain: {Domain} using strategy 5 with to pdc {Server}", domainName, primaryDomainController);
                connection = CheckCacheConnection(portConnectionResult.connection, tempDomainName, globalCatalog,
                    forceCreateNewConnection);
                return (true, connection);
            }
            
            //Loop over all other domain controllers and see if we can make a good connection to any
            foreach (DomainController dc in domainObject.DomainControllers)
            {
                portConnectionResult =
                    await CreateLDAPConnectionWithPortCheck(primaryDomainController, authType, globalCatalog);
                if (portConnectionResult.success)
                {
                    _log.LogDebug("Successfully created ldap connection for domain: {Domain} using strategy 6 with to pdc {Server}", domainName, primaryDomainController);
                    connection = CheckCacheConnection(portConnectionResult.connection, tempDomainName, globalCatalog,
                        forceCreateNewConnection);
                    return (true, connection);
                }
            }

            _log.LogWarning("Exhausted all potential methods of creating ldap connection to {DomainName}", domainName);
            return (false, null);
        }
        catch (LdapAuthenticationException e)
        {
            _log.LogError("Error connecting to {Domain}: credentials are invalid (error code {ErrorCode})", domainName,
                e.LdapException.ErrorCode);
            return (false, null);
        }
        catch (NoLdapDataException)
        {
            _log.LogError("No data returned for domain {Domain} during initial LDAP test.", domainName);
            return (false, null);
        }
    }
    
    private async Task<(bool success, LdapConnection connection)> CreateLDAPConnectionWithPortCheck(string target, AuthType authType, bool globalCatalog)
    {
        if (globalCatalog)
        {
            if (await _portScanner.CheckPort(target, _ldapConfig.GetGCPort(true)) || (!_ldapConfig.ForceSSL &&
                    await _portScanner.CheckPort(target, _ldapConfig.GetGCPort(false))))
            {
                return (CreateLdapConnection(target, authType, true, out var connection), connection);
            }
        }
        else
        {
            if (await _portScanner.CheckPort(target, _ldapConfig.GetPort(true)) || (!_ldapConfig.ForceSSL && await _portScanner.CheckPort(target, _ldapConfig.GetPort(false))))
            {
                return (CreateLdapConnection(target, authType, true, out var connection), connection);
            }
        }
            
        return (false, null);
    }
    
    private LdapConnection CheckCacheConnection(LdapConnection connection, string domainName, bool globalCatalog, bool forceCreateNewConnection)
    {
        LDAPConnectionCacheKey cacheKey;
        if (_ldapConfig.Server != null)
        {
            cacheKey = new LDAPConnectionCacheKey(_ldapConfig.Server, globalCatalog);
        }
        else
        {
            if (!GetDomainSidFromDomainName(domainName, out var cacheIdentifier))
            {
                //This is kinda gross, but its another way to get the correct domain sid
                if (!connection.GetNamingContextSearchBase(NamingContexts.Default, out var searchBase) || !GetDomainSidFromConnection(connection, searchBase, out cacheIdentifier))
                {
                    /*
                     * If we get here, we couldn't resolve a domain sid, which is hella bad, but we also want to keep from creating a shitton of new connections
                     * Cache using the domainname and pray it all works out
                     */
                    cacheIdentifier = domainName.ToUpper().Trim();
                }
            }

            cacheKey = new LDAPConnectionCacheKey(cacheIdentifier, globalCatalog);
        }
        
        if (forceCreateNewConnection)
        {
            return _ldapConnectionCache.AddOrUpdate(cacheKey, connection, (_, existingConnection) =>
            {
                existingConnection.Dispose();
                return connection;
            });
        }

        return _ldapConnectionCache.AddOrUpdate(cacheKey, connection, (_, existingConnection) =>
        {
            connection.Dispose();
            return existingConnection;
        });
    }
    
    private bool GetCachedConnection(string domain, bool globalCatalog, out LdapConnection connection)
    {
        LDAPConnectionCacheKey cacheKey;
        //If server is set via our config, we'll always just use this as the cache key
        if (_ldapConfig.Server != null)
        {
            cacheKey = new LDAPConnectionCacheKey(_ldapConfig.Server, globalCatalog);
            return _ldapConnectionCache.TryGetValue(cacheKey, out connection);
        }
        
        if (GetDomainSidFromDomainName(domain, out var domainSid))
        {
            cacheKey = new LDAPConnectionCacheKey(domainSid, globalCatalog);
            if (_ldapConnectionCache.TryGetValue(cacheKey, out connection))
            {
                return true;
            }
        }

        cacheKey = new LDAPConnectionCacheKey(domain.ToUpper().Trim(), globalCatalog);
        return _ldapConnectionCache.TryGetValue(cacheKey, out connection);
    }
    

    private bool GetDomainSidFromConnection(LdapConnection connection, string searchBase, out string domainSid)
    {
        try
        {
            //This ldap filter searches for domain controllers
            //Searches for any accounts with a UAC value inclusive of 8192 bitwise
            //8192 is the flag for SERVER_TRUST_ACCOUNT, which is set only on Domain Controllers
            var searchRequest = new SearchRequest(searchBase,
                "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
                SearchScope.Subtree, new[] { "objectsid"});

            var response = (SearchResponse)connection.SendRequest(searchRequest);
            if (response == null || response.Entries.Count == 0)
            {
                domainSid = "";
                return false;
            }

            var entry = response.Entries[0];
            var sid = entry.GetSid();
            domainSid = sid.Substring(0, sid.LastIndexOf('-')).ToUpper(); 
            return true;
        }
        catch (LdapException)
        {
            _log.LogWarning("Failed grabbing domainsid from ldap for {domain}", searchBase);
            domainSid = "";
            return false;
        }
    }

    private bool CreateLdapConnection(string target, AuthType authType, bool globalCatalog, out LdapConnection connection)
    {
        var baseConnection = CreateBaseConnection(target, true, authType, globalCatalog);
        if (TestLdapConnection(baseConnection, target))
        {
            connection = baseConnection;
            return true;
        }

        try
        {
            baseConnection.Dispose();
        }
        catch
        {
            //this is just in case
        }

        if (_ldapConfig.ForceSSL)
        {
            connection = null;
            return false;
        }
        
        baseConnection = CreateBaseConnection(target, false, authType, globalCatalog);
        if (TestLdapConnection(baseConnection, target))
        {
            connection = baseConnection;
            return true;
        }
        
        try
        {
            baseConnection.Dispose();
        }
        catch
        {
            //this is just in case
        }

        connection = null;
        return false;
    }

    private LdapConnection CreateBaseConnection(string directoryIdentifier, bool ssl, AuthType authType,
        bool globalCatalog)
    {
        var port = globalCatalog ? _ldapConfig.GetGCPort(ssl) : _ldapConfig.GetPort(ssl);
        var identifier = new LdapDirectoryIdentifier(directoryIdentifier, port, false, false);
        var connection = new LdapConnection(identifier) { Timeout = new TimeSpan(0, 0, 5, 0) };
        
        //These options are important!
        connection.SessionOptions.ProtocolVersion = 3;
        //Referral chasing does not work with paged searches 
        connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
        if (ssl)
        {
            connection.SessionOptions.SecureSocketLayer = true;    
        }
        
        if (_ldapConfig.DisableSigning)
        {
            connection.SessionOptions.Sealing = false;
            connection.SessionOptions.Signing = false;
        }
            
        if (_ldapConfig.DisableCertVerification)
            connection.SessionOptions.VerifyServerCertificate = (_, _) => true;
            
        if (_ldapConfig.Username != null)
        {
            var cred = new NetworkCredential(_ldapConfig.Username, _ldapConfig.Password);
            connection.Credential = cred;
        }
            
        connection.AuthType = authType;

        return connection;
    }

    private struct LdapFailure
    {
        public LdapFailureReason FailureReason { get; set; }
        public string Message { get; set; }
    }
    
    /// <summary>
    /// Tests whether an LDAP connection is working
    /// </summary>
    /// <param name="connection"></param>
    /// <param name="identifier"></param>
    /// <returns></returns>
    /// <exception cref="LdapAuthenticationException">Something is wrong with the supplied credentials</exception>
    /// <exception cref="NoLdapDataException">A connection "succeeded" but no data was returned. This can be related to kerberos auth across trusts or just simply lack of permissions</exception>
    private bool TestLdapConnection(LdapConnection connection, string identifier)
    {
        try
        {
            //Attempt an initial bind. If this fails, likely auth is invalid, or its not a valid target
            connection.Bind();
        }
        catch (LdapException e)
        {
            //TODO: Maybe look at this and find a better way?
            if (e.ErrorCode is (int)LdapErrorCodes.InvalidCredentials or (int)ResultCode.InappropriateAuthentication)
            {
                connection.Dispose();
                throw new LdapAuthenticationException(e);
            }
            return false;
        }
        catch (Exception e)
        {
            return false;
        }

        SearchResponse response;
        try
        {
            //Do an initial search request to get the rootDSE
            //This ldap filter is equivalent to (objectclass=*)
            var searchRequest = CreateSearchRequest("", new LDAPFilter().AddAllObjects().GetFilter(),
                SearchScope.Base, null);

            response = (SearchResponse)connection.SendRequest(searchRequest);
        }
        catch (LdapException e)
        {
            /*
             * If we can't send the initial search request, its unlikely any other search requests will work so we will immediately return false
             */
            _log.LogDebug(e, "TestLdapConnection failed during search request against target {Target}", identifier);
            return false;
        }
        
        if (response?.Entries == null || response.Entries.Count == 0)
        {
            /*
             * This can happen for one of two reasons, either we dont have permission to query AD or we're authenticating
             * across external trusts with kerberos authentication without Forest Search Order properly configured.
             * Either way, this connection isn't useful for us because we're not going to get data, so return false
             */
            
            _log.LogDebug("TestLdapConnection failed to return results against target {Target}", identifier);
            connection.Dispose();
            throw new NoLdapDataException();
        }
        
        return true;
    }

    private SearchRequest CreateSearchRequest(string distinguishedName, string ldapFilter, SearchScope searchScope,
        string[] attributes)
    {
        var searchRequest = new SearchRequest(distinguishedName, ldapFilter,
            searchScope, attributes); 
        searchRequest.Controls.Add(new SearchOptionsControl(SearchOption.DomainScope));
        return searchRequest;
    }

    public bool GetDomainSidFromDomainName(string domainName, out string domainSid)
    {
        if (Cache.GetDomainSidMapping(domainName, out domainSid))
        {
            return true;
        }

        try
        {
            var entry = new DirectoryEntry($"LDAP://{domainName}");
            //Force load objectsid into the object cache
            entry.RefreshCache(new[] {"objectSid"});
            var sid = entry.GetSid();
            if (sid != null)
            {
                Cache.AddDomainSidMapping(domainName, sid);
                domainSid = sid;
                return true;
            }
        }
        catch
        {
            //we expect this to fail sometimes
        }

        if (GetDomain(domainName, out var domainObject))
        {
            try
            {
                domainSid = domainObject.GetDirectoryEntry().GetSid();
                if (domainSid != null)
                {
                    Cache.AddDomainSidMapping(domainName, domainSid);
                    return true;
                }
            }
            catch
            {
                //we expect this to fail sometimes (not sure why, but better safe than sorry)
            }
        }

        foreach (var name in _translateNames)
        {
            try
            {
                var account = new NTAccount(domainName, name);
                var sid = (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));
                domainSid = sid.AccountDomainSid.ToString();
                Cache.AddDomainSidMapping(domainName, domainSid);
                return true;
            }
            catch
            {
                //We expect this to fail if the username doesn't exist in the domain
            }
        }

        return false;
    }

    private string ResolveDomainCrossRef(string domainName)
    {
        
    }
    
    /// <summary>
    /// Attempts to get the Domain object representing the target domain. If null is specified for the domain name, gets the user's current domain
    /// </summary>
    /// <param name="domain"></param>
    /// <param name="domainName"></param>
    /// <returns></returns>
    public bool GetDomain(string domainName, out Domain domain)
    {
        var cacheKey = domainName ?? _nullCacheKey;
        if (_domainCache.TryGetValue(cacheKey, out domain)) return true;

        try
        {
            DirectoryContext context;
            if (_ldapConfig.Username != null)
            {
                context = domainName != null
                    ? new DirectoryContext(DirectoryContextType.Domain, domainName, _ldapConfig.Username,
                        _ldapConfig.Password)
                    : new DirectoryContext(DirectoryContextType.Domain, _ldapConfig.Username,
                        _ldapConfig.Password);
            }
            else
            {
                context = domainName != null
                    ? new DirectoryContext(DirectoryContextType.Domain, domainName)
                    : new DirectoryContext(DirectoryContextType.Domain);
            }

            domain = Domain.GetDomain(context);
            if (domain == null) return false;
            _domainCache.TryAdd(cacheKey, domain);
            return true;

        }
        catch (Exception e)
        {
            _log.LogDebug(e, "GetDomain call failed for domain name {Name}", domainName);
            return false;
        }
    }
    
    /// <summary>
    /// Attempts to get the Domain object representing the target domain. If null is specified for the domain name, gets the user's current domain
    /// </summary>
    /// <param name="domain"></param>
    /// <param name="domainName"></param>
    /// <returns></returns>
    public bool GetDomain(out Domain domain)
    {
        var cacheKey = _nullCacheKey;
        if (_domainCache.TryGetValue(cacheKey, out domain)) return true;

        try
        {
            var context= _ldapConfig.Username != null
                ? new DirectoryContext(DirectoryContextType.Domain, _ldapConfig.Username,
                    _ldapConfig.Password)
                : new DirectoryContext(DirectoryContextType.Domain);

            domain = Domain.GetDomain(context);
            _domainCache.TryAdd(cacheKey, domain);
            return true;
        }
        catch (Exception e)
        {
            _log.LogDebug(e, "GetDomain call failed for blank domain");
            return false;
        }
    }

}