using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Runtime.CompilerServices;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib;

public interface ILdapUtilsNew {
    IAsyncEnumerable<LdapResult<ISearchResultEntry>> Query(LdapQueryParameters queryParameters,
        CancellationToken cancellationToken);

    IAsyncEnumerable<LdapResult<ISearchResultEntry>> PagedQuery(LdapQueryParameters queryParameters,
        CancellationToken cancellationToken);

    IAsyncEnumerable<Result<string>> RangedRetrieval(string distinguishedName,
        string attributeName, CancellationToken cancellationToken = new());

    Task<(bool Success, TypedPrincipal Principal)> ResolveIDAndType(SecurityIdentifier securityIdentifier,
        string objectDomain);

    Task<(bool Success, TypedPrincipal Principal)>
        ResolveIDAndType(string identifier, string objectDomain);

    Task<(bool Success, TypedPrincipal WellKnownPrincipal)> GetWellKnownPrincipal(
        string securityIdentifier, string objectDomain);

    Task<(bool Success, string DomainName)> GetDomainNameFromSid(string sid);
    Task<(bool Success, string DomainSid)> GetDomainSidFromDomainName(string domainName);
    bool GetDomain(string domainName, out System.DirectoryServices.ActiveDirectory.Domain domain);
    bool GetDomain(out System.DirectoryServices.ActiveDirectory.Domain domain);
    Task<(bool Success, TypedPrincipal Principal)> ResolveAccountName(string name, string domain);
    Task<(bool Success, string SecurityIdentifier)> ResolveHostToSid(string host, string domain);
    Task<(bool Success, string[] Sids)> GetGlobalCatalogMatches(string name, string domain);
    Task<(bool Success, TypedPrincipal Principal)> ResolveCertTemplateByProperty(string propValue, string propName, string containerDN, string domainName);
    ActiveDirectorySecurityDescriptor MakeSecurityDescriptor();

    public Task<(bool Success, TypedPrincipal Principal)> ConvertLocalWellKnownPrincipal(SecurityIdentifier sid,
        string computerDomainSid, string computerDomain);
}