using System;
using System.Collections.Concurrent;
using System.DirectoryServices;
using System.Security.Principal;
using System.Threading.Tasks;

namespace SharpHoundCommonLib;

public class ConnectionPoolManager : IDisposable{
    private readonly ConcurrentDictionary<string, LdapConnectionPool> _pools = new();
    private readonly LDAPConfig _ldapConfig;
    private readonly string[] _translateNames = { "Administrator", "admin" };

    public ConnectionPoolManager(LDAPConfig config) {
        _ldapConfig = config;
    }

    public async Task<(bool Success, LdapConnectionWrapperNew connectionWrapper, string Message)> GetLdapConnection(
        string identifier, bool globalCatalog) {
        var resolved = ResolveIdentifier(identifier);

        if (!_pools.TryGetValue(identifier, out var pool)) {
            pool = new LdapConnectionPool(resolved, _ldapConfig);
            _pools.TryAdd(identifier, pool);
        }

        if (globalCatalog) {
            return await pool.GetGlobalCatalogConnectionAsync();
        }
        return await pool.GetConnectionAsync();
    }
    
    public async Task<(bool Success, LdapConnectionWrapperNew connectionWrapper, string Message)> GetLdapConnectionForServer(
        string identifier, string server, bool globalCatalog) {
        var resolved = ResolveIdentifier(identifier);

        if (!_pools.TryGetValue(identifier, out var pool)) {
            pool = new LdapConnectionPool(resolved, _ldapConfig);
            _pools.TryAdd(identifier, pool);
        }
        
        return await pool.GetConnectionForSpecificServerAsync(server, globalCatalog);
    }

    private string ResolveIdentifier(string identifier) {
        return GetDomainSidFromDomainName(identifier, out var sid) ? sid : identifier;
    }
    
    private bool GetDomainSidFromDomainName(string domainName, out string domainSid) {
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

        if (LDAPUtilsNew.GetDomain(domainName, _ldapConfig, out var domainObject))
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

    public void Dispose() {
        foreach (var kv in _pools)
        {
            kv.Value.Dispose();
        }
        
        _pools.Clear();
    }
}