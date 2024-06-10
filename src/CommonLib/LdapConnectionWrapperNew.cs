using System;
using System.DirectoryServices.Protocols;
using SharpHoundCommonLib.Enums;

namespace SharpHoundCommonLib;

public class LdapConnectionWrapperNew
{
    public LdapConnection Connection;
    private string _domainSearchBase;
    private string _configurationSearchBase;
    private string _schemaSearchBase;
    private const string Unknown = "UNKNOWN";

    public LdapConnectionWrapperNew(LdapConnection connection)
    {
        Connection = connection;
    }

    public bool GetSearchBase(NamingContexts context, out string searchBase)
    {
        searchBase = GetSavedContext(context);
        if (searchBase != null)
        {
            return true;
        }

        if (Connection.GetNamingContextSearchBase(context, out searchBase))
        {
            SaveContext(context, searchBase);
            return true;
        }
        
        return false;
    }

    private string GetSavedContext(NamingContexts context)
    {
        return context switch
        {
            NamingContexts.Configuration => _configurationSearchBase,
            NamingContexts.Default => _domainSearchBase,
            NamingContexts.Schema => _schemaSearchBase,
            _ => throw new ArgumentOutOfRangeException(nameof(context), context, null)
        };
    }

    public void SaveContext(NamingContexts context, string searchBase)
    {
        switch (context)
        {
            case NamingContexts.Default:
                _domainSearchBase = searchBase;
                break;
            case NamingContexts.Configuration:
                _configurationSearchBase = searchBase;
                break;
            case NamingContexts.Schema:
                _schemaSearchBase = searchBase;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(context), context, null);
        }
    }
}