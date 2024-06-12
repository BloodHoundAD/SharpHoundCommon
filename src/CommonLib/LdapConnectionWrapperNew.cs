using System;
using System.DirectoryServices.Protocols;
using SharpHoundCommonLib.Enums;

namespace SharpHoundCommonLib;

public class LdapConnectionWrapperNew
{
    public LdapConnection Connection { get; private set; }
    private readonly ISearchResultEntry _searchResultEntry;
    private string _domainSearchBase;
    private string _configurationSearchBase;
    private string _schemaSearchBase;
    private string _server;
    private const string Unknown = "UNKNOWN";

    public LdapConnectionWrapperNew(LdapConnection connection, ISearchResultEntry entry)
    {
        Connection = connection;
        _searchResultEntry = entry;
    }

    public void CopyContexts(LdapConnectionWrapperNew other) {
        _domainSearchBase = other._domainSearchBase;
        _configurationSearchBase = other._configurationSearchBase;
        _schemaSearchBase = other._schemaSearchBase;
        _server = other._server;
    }

    public bool GetServer(out string server) {
        if (_server != null) {
            server = _server;
            return true;
        }

        _server = _searchResultEntry.GetProperty(LDAPProperties.DNSHostName);
        server = _server;
        return server != null;
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
}