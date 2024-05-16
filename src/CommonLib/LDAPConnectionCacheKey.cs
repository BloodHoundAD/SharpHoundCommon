using System.Collections.Concurrent;
using System.DirectoryServices.Protocols;

namespace SharpHoundCommonLib
{
    // public class LDAPConnectionCacheKey
    // {
    //     public int Port;
    //     public bool GlobalCatalog;
    //     public string Domain;

    //     protected bool Equals(LDAPConnectionCacheKey other)
    //     {
    //         return Port == other.Port && GlobalCatalog == other.GlobalCatalog && Domain == other.Domain;
    //     }

    //     public override bool Equals(object obj)
    //     {
    //         if (ReferenceEquals(null, obj)) return false;
    //         if (ReferenceEquals(this, obj)) return true;
    //         if (obj.GetType() != this.GetType()) return false;
    //         return Equals((LDAPConnectionCacheKey)obj);
    //     }

    //     public override int GetHashCode()
    //     {
    //         unchecked
    //         {
    //             var hashCode = Port;
    //             hashCode = (hashCode * 397) ^ GlobalCatalog.GetHashCode();
    //             hashCode = (hashCode * 397) ^ (Domain != null ? Domain.GetHashCode() : 0);
    //             return hashCode;
    //         }
    //     }
    // }

    public class LdapConnectionWrapper
    {
        public LdapConnection Connection { get; set; }
        public string DomainName {get; set; }
        public int Port {get; set; }
        public bool IsGlobalCatalog { get; set; }
    }

    public class LDAPConnectionCache
    {
        private ConcurrentDictionary<string, LdapConnectionWrapper> _connectionCache = new ConcurrentDictionary<string, LdapConnectionWrapper>();

        public void Add(LdapConnectionWrapper connectionWrapper)
        {
            var normalizedDomainName = connectionWrapper.DomainName.ToUpper();
            _connectionCache.AddOrUpdate(normalizedDomainName, connectionWrapper, (_, ldapConnection) =>
                {
                    ldapConnection.Connection.Dispose();
                    return connectionWrapper;
                });
        }

        public LdapConnectionWrapper Get(string domainName)
        {
            if (_connectionCache.TryGetValue(domainName.ToUpper(), out var connectionWrapper))
            {
                return connectionWrapper;
            }

            return null;
        }
    }
}