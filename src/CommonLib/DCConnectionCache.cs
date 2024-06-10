using System.Collections.Concurrent;
using System.DirectoryServices.Protocols;

namespace SharpHoundCommonLib
{
    public class DCConnectionCache
    {
        private readonly ConcurrentDictionary<LDAPConnectionCacheKey, LdapConnection> _ldapConnectionCache;

        public DCConnectionCache()
        {
            _ldapConnectionCache = new ConcurrentDictionary<LDAPConnectionCacheKey, LdapConnection>();
        }

        public bool TryGet(string domainName, bool isGlobalCatalog, out LdapConnection connection)
        {
            var key = GetKey(domainName, isGlobalCatalog);
            return _ldapConnectionCache.TryGetValue(key, out connection);
        }

        public LdapConnection AddOrUpdate(string domainName, bool isGlobalCatalog, LdapConnection connection)
        {
            var cacheKey = GetKey(domainName, isGlobalCatalog);
            return _ldapConnectionCache.AddOrUpdate(cacheKey, connection, (_, existingConnection) =>
            {
                existingConnection.Dispose();
                return connection;
            });
        }

        public LdapConnection TryAdd(string domainName, bool isGlobalCatalog, LdapConnection connection)
        {
            var cacheKey = GetKey(domainName, isGlobalCatalog);
            return _ldapConnectionCache.AddOrUpdate(cacheKey, connection, (_, existingConnection) =>
            {
                connection.Dispose();
                return existingConnection;
            });
        }

        private LDAPConnectionCacheKey GetKey(string domainName, bool isGlobalCatalog)
        {
            return new LDAPConnectionCacheKey(domainName, isGlobalCatalog);
        }

        private class LDAPConnectionCacheKey
        {
            public bool GlobalCatalog { get; }
            public string Domain { get; }
            public string Server { get; set; }

            public LDAPConnectionCacheKey(string domain, bool globalCatalog)
            {
                GlobalCatalog = globalCatalog;
                Domain = domain;
            }

            protected bool Equals(LDAPConnectionCacheKey other)
            {
                return GlobalCatalog == other.GlobalCatalog && Domain == other.Domain;
            }

            public override bool Equals(object obj)
            {
                if (ReferenceEquals(null, obj)) return false;
                if (ReferenceEquals(this, obj)) return true;
                if (obj.GetType() != this.GetType()) return false;
                return Equals((LDAPConnectionCacheKey)obj);
            }

            public override int GetHashCode()
            {
                unchecked
                {
                    return (GlobalCatalog.GetHashCode() * 397) ^ (Domain != null ? Domain.GetHashCode() : 0);
                }
            }
        }
    }
}