using System;
using System.Collections.Concurrent;
using System.DirectoryServices;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Processors;

namespace SharpHoundCommonLib;

public class ConnectionPoolManager : IDisposable{
    private readonly ConcurrentDictionary<string, LdapConnectionPool> _pools = new();
    private readonly LDAPConfig _ldapConfig;
    private readonly string[] _translateNames = { "Administrator", "admin" };
    private readonly ConcurrentDictionary<string, string> _resolvedIdentifiers = new(StringComparer.OrdinalIgnoreCase);
    private readonly ILogger _log;
    private readonly PortScanner _portScanner;

    public ConnectionPoolManager(LDAPConfig config, ILogger log = null, PortScanner scanner = null) {
        _ldapConfig = config;
        _log = log ?? Logging.LogProvider.CreateLogger("ConnectionPoolManager");
        _portScanner = scanner ?? new PortScanner();
    }

    public void ReleaseConnection(LdapConnectionWrapperNew connectionWrapper, bool connectionFaulted = false) {
        //I dont think this is possible, but at least account for it
        if (!_pools.TryGetValue(connectionWrapper.PoolIdentifier, out var pool)) {
            connectionWrapper.Connection.Dispose();
            return;
        }
        
        pool.ReleaseConnection(connectionWrapper, connectionFaulted);
    }

    public async Task<(bool Success, LdapConnectionWrapperNew ConnectionWrapper, string Message)> GetLdapConnection(
        string identifier, bool globalCatalog) {
        var resolved = ResolveIdentifier(identifier);

        if (!_pools.TryGetValue(identifier, out var pool)) {
            pool = new LdapConnectionPool(resolved, _ldapConfig,scanner: _portScanner);
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
            pool = new LdapConnectionPool(resolved, _ldapConfig,scanner: _portScanner);
            _pools.TryAdd(identifier, pool);
        }
        
        return await pool.GetConnectionForSpecificServerAsync(server, globalCatalog);
    }

    private string ResolveIdentifier(string identifier) {
        if (_resolvedIdentifiers.TryGetValue(identifier, out var resolved)) {
            return resolved;
        }


        if (GetDomainSidFromDomainName(identifier, out var sid)) {
            _log.LogDebug("Resolved identifier {Identifier} to {Resolved}", identifier, sid);
            _resolvedIdentifiers.TryAdd(identifier, sid);
            return sid;
        }
            
        return identifier;
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

        if (LdapUtilsNew.GetDomain(domainName, _ldapConfig, out var domainObject))
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