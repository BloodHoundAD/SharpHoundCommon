using System;
using System.DirectoryServices.Protocols;
using SharpHoundCommonLib.Enums;

namespace SharpHoundCommonLib;

public class LdapQueryParameters
{
    public string LDAPFilter { get; set; }
    public SearchScope SearchScope { get; set; } = SearchScope.Subtree;
    public string[] Attributes { get; set; } = Array.Empty<string>();
    public string DomainName { get; set; }
    public bool GlobalCatalog { get; set; }
    public bool IncludeSecurityDescriptor { get; set; } = false;
    public bool IncludeDeleted { get; set; } = false;
    public string SearchBase { get; set; }
    public NamingContext NamingContext { get; set; } = NamingContext.Default;
    public bool ThrowException { get; set; } = false;

    public string GetQueryInfo()
    {
        return $"Query Information - Filter: {LDAPFilter}, Domain: {DomainName}, GlobalCatalog: {GlobalCatalog}, ADSPath: {SearchBase}";
    }
}