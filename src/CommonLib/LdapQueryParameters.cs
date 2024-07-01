using System;
using System.DirectoryServices.Protocols;
using SharpHoundCommonLib.Enums;

namespace SharpHoundCommonLib;

public class LdapQueryParameters
{
    private string _searchBase;
    private string _relativeSearchBase;
    public string LDAPFilter { get; set; }
    public SearchScope SearchScope { get; set; } = SearchScope.Subtree;
    public string[] Attributes { get; set; } = Array.Empty<string>();
    public string DomainName { get; set; }
    public bool GlobalCatalog { get; set; }
    public bool IncludeSecurityDescriptor { get; set; } = false;
    public bool IncludeDeleted { get; set; } = false;

    public string SearchBase {
        get => _searchBase;
        set {
            _relativeSearchBase = null;
            _searchBase = value;
        }
    }

    public string RelativeSearchBase {
        get => _relativeSearchBase;
        set {
            _relativeSearchBase = value;
            _searchBase = null;
        }
    }

    public NamingContext NamingContext { get; set; } = NamingContext.Default;
    public bool ThrowException { get; set; } = false;

    public string GetQueryInfo()
    {
        return $"Query Information - Filter: {LDAPFilter}, Domain: {DomainName}, GlobalCatalog: {GlobalCatalog}, ADSPath: {SearchBase}";
    }
}