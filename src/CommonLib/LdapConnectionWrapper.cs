using System;
using System.DirectoryServices.Protocols;
using SharpHoundCommonLib.Enums;

namespace SharpHoundCommonLib {
    public class LdapConnectionWrapper {
        public LdapConnection Connection { get; private set; }
        private readonly IDirectoryObject _rootDseEntry;
        private string _domainSearchBase;
        private string _configurationSearchBase;
        private string _schemaSearchBase;
        private string _server;
        private string Guid { get; set; }
        public readonly bool GlobalCatalog;
        public readonly string PoolIdentifier;

        public LdapConnectionWrapper(LdapConnection connection, IDirectoryObject rootDseEntry, bool globalCatalog,
            string poolIdentifier) {
            Connection = connection;
            _rootDseEntry = rootDseEntry;
            Guid = new Guid().ToString();
            GlobalCatalog = globalCatalog;
            PoolIdentifier = poolIdentifier;
        }
        
        public string GetServer() {
            if (_server != null) {
                return _server;
            }

            _server = _rootDseEntry.GetProperty(LDAPProperties.DNSHostName);
            return _server;
        }

        public bool GetSearchBase(NamingContext context, out string searchBase) {
            searchBase = GetSavedContext(context);
            if (searchBase != null) {
                return true;
            }

            searchBase = context switch {
                NamingContext.Default => _rootDseEntry.GetProperty(LDAPProperties.DefaultNamingContext),
                NamingContext.Configuration =>
                    _rootDseEntry.GetProperty(LDAPProperties.ConfigurationNamingContext),
                NamingContext.Schema => _rootDseEntry.GetProperty(LDAPProperties.SchemaNamingContext),
                _ => throw new ArgumentOutOfRangeException(nameof(context), context, null)
            };

            if (searchBase != null) {
                SaveContext(context, searchBase);
                return true;
            }

            return false;
        }

        private string GetSavedContext(NamingContext context) {
            return context switch {
                NamingContext.Configuration => _configurationSearchBase,
                NamingContext.Default => _domainSearchBase,
                NamingContext.Schema => _schemaSearchBase,
                _ => throw new ArgumentOutOfRangeException(nameof(context), context, null)
            };
        }

        public void SaveContext(NamingContext context, string searchBase) {
            switch (context) {
                case NamingContext.Default:
                    _domainSearchBase = searchBase;
                    break;
                case NamingContext.Configuration:
                    _configurationSearchBase = searchBase;
                    break;
                case NamingContext.Schema:
                    _schemaSearchBase = searchBase;
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(context), context, null);
            }
        }

        protected bool Equals(LdapConnectionWrapper other) {
            return Guid == other.Guid;
        }

        public override bool Equals(object obj) {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((LdapConnectionWrapper)obj);
        }

        public override int GetHashCode() {
            return (Guid != null ? Guid.GetHashCode() : 0);
        }
    }
}