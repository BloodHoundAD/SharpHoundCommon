using System;
using System.DirectoryServices.Protocols;
using SharpHoundCommonLib.Enums;

namespace SharpHoundCommonLib {
    public class LdapConnectionWrapperNew
    {
        public LdapConnection Connection { get; private set; }
        private readonly ISearchResultEntry _searchResultEntry;
        private string _domainSearchBase;
        private string _configurationSearchBase;
        private string _schemaSearchBase;
        private string _server;
        private string Guid { get; set; }
        public bool GlobalCatalog;
        public string PoolIdentifier;

        public LdapConnectionWrapperNew(LdapConnection connection, ISearchResultEntry entry, bool globalCatalog, string poolIdentifier)
    {
        Connection = connection;
        _searchResultEntry = entry;
        Guid = new Guid().ToString();
        GlobalCatalog = globalCatalog;
        PoolIdentifier = poolIdentifier;
    }

        public void CopyContexts(LdapConnectionWrapperNew other) {
        _domainSearchBase = other._domainSearchBase;
        _configurationSearchBase = other._configurationSearchBase;
        _schemaSearchBase = other._schemaSearchBase;
        _server = other._server;
    }

        public string GetServer() {
        if (_server != null) {
            return _server;
        }

        _server = _searchResultEntry.GetProperty(LDAPProperties.DNSHostName);
        return _server;
    }

        public bool GetSearchBase(NamingContext context, out string searchBase)
    {
        searchBase = GetSavedContext(context);
        if (searchBase != null)
        {
            return true;
        }
        
        searchBase = context switch {
            NamingContext.Default => _searchResultEntry.GetProperty(LDAPProperties.DefaultNamingContext),
            NamingContext.Configuration => _searchResultEntry.GetProperty(LDAPProperties.ConfigurationNamingContext),
            NamingContext.Schema => _searchResultEntry.GetProperty(LDAPProperties.SchemaNamingContext),
            _ => throw new ArgumentOutOfRangeException(nameof(context), context, null)
        };

        if (searchBase != null) {
            SaveContext(context, searchBase);
            return true;
        }
        
        return false;
    }

        private string GetSavedContext(NamingContext context)
    {
        return context switch
        {
            NamingContext.Configuration => _configurationSearchBase,
            NamingContext.Default => _domainSearchBase,
            NamingContext.Schema => _schemaSearchBase,
            _ => throw new ArgumentOutOfRangeException(nameof(context), context, null)
        };
    }

        public void SaveContext(NamingContext context, string searchBase)
    {
        switch (context)
        {
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

        protected bool Equals(LdapConnectionWrapperNew other) {
        return Guid == other.Guid;
    }

        public override bool Equals(object obj) {
        if (ReferenceEquals(null, obj)) return false;
        if (ReferenceEquals(this, obj)) return true;
        if (obj.GetType() != this.GetType()) return false;
        return Equals((LdapConnectionWrapperNew)obj);
    }

        public override int GetHashCode() {
        return (Guid != null ? Guid.GetHashCode() : 0);
    }
    }
}