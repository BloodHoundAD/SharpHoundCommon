using System.Collections.Generic;
using System.Security.AccessControl;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Threading;
using System.Threading.Tasks;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib
{
    public interface ILDAPUtils
    {
        void SetLDAPConfig(LDAPConfig config);
        string[] GetUserGlobalCatalogMatches(string name);
        TypedPrincipal ResolveIDAndType(string id, string domain);
        Label LookupSidType(string sid, string domain);
        Label LookupGuidType(string guid, string domain);
        string GetDomainNameFromSid(string sid);
        Task<string> GetSidFromDomainName(string domainName);
        string ConvertWellKnownPrincipal(string sid, string domain);
        bool GetWellKnownPrincipal(string sid, string domain, out TypedPrincipal commonPrincipal);

        /// <summary>
        /// Performs Attribute Ranged Retrieval
        /// https://docs.microsoft.com/en-us/windows/win32/adsi/attribute-range-retrieval
        /// The function self-determines the range and internally handles the maximum step allowed by the server
        /// </summary>
        /// <param name="distinguishedName"></param>
        /// <param name="attributeName"></param>
        /// <returns></returns>
        IEnumerable<string> DoRangedRetrieval(string distinguishedName, string attributeName);

        /// <summary>
        /// Takes a host in most applicable forms from AD and attempts to resolve it into a SID.
        /// </summary>
        /// <param name="hostname"></param>
        /// <param name="domain"></param>
        /// <returns></returns>
        Task<string> ResolveHostToSid(string hostname, string domain);

        /// <summary>
        /// Attempts to convert a bare account name (usually from session enumeration) to its corresponding ID and object type
        /// </summary>
        /// <param name="name"></param>
        /// <param name="domain"></param>
        /// <returns></returns>
        Task<TypedPrincipal> ResolveAccountName(string name, string domain);

        /// <summary>
        /// Attempts to convert a distinguishedname to its corresponding ID and object type.
        /// </summary>
        /// <param name="dn">DistinguishedName</param>
        /// <returns>A <c>TypedPrincipal</c> object with the SID and Label</returns>
        TypedPrincipal ResolveDistinguishedName(string dn);

        /// <summary>
        /// Performs an LDAP query using the parameters specified by the user.
        /// </summary>
        /// <param name="ldapFilter">LDAP filter</param>
        /// <param name="scope">SearchScope to query</param>
        /// <param name="props">LDAP properties to fetch for each object</param>
        /// <param name="cancellationToken">Cancellation Token</param>
        /// <param name="includeAcl">Include the DACL and Owner values in the NTSecurityDescriptor</param>
        /// <param name="showDeleted">Include deleted objects</param>
        /// <param name="domainName">Domain to query</param>
        /// <param name="adsPath">ADS path to limit the query too</param>
        /// <param name="globalCatalog">Use the global catalog instead of the regular LDAP server</param>
        /// <param name="skipCache">Skip the connection cache and force a new connection. You must dispose of this connection yourself.</param>
        /// <returns>All LDAP search results matching the specified parameters</returns>
        IEnumerable<ISearchResultEntry> QueryLDAP(string ldapFilter, SearchScope scope,
            string[] props, CancellationToken cancellationToken, string domainName = null, bool includeAcl = false, bool showDeleted = false, string adsPath = null, bool globalCatalog = false, bool skipCache = false);

        /// <summary>
        /// Performs an LDAP query using the parameters specified by the user.
        /// </summary>
        /// <param name="ldapFilter">LDAP filter</param>
        /// <param name="scope">SearchScope to query</param>
        /// <param name="props">LDAP properties to fetch for each object</param>
        /// <param name="includeAcl">Include the DACL and Owner values in the NTSecurityDescriptor</param>
        /// <param name="showDeleted">Include deleted objects</param>
        /// <param name="domainName">Domain to query</param>
        /// <param name="adsPath">ADS path to limit the query too</param>
        /// <param name="globalCatalog">Use the global catalog instead of the regular LDAP server</param>
        /// <param name="skipCache">Skip the connection cache and force a new connection. You must dispose of this connection yourself.</param>
        /// <returns>All LDAP search results matching the specified parameters</returns>
        IEnumerable<ISearchResultEntry> QueryLDAP(string ldapFilter, SearchScope scope,
            string[] props, string domainName = null, bool includeAcl = false, bool showDeleted = false, string adsPath = null, bool globalCatalog = false, bool skipCache = false);

        Forest GetForest(string domainName = null);

        ActiveDirectorySecurityDescriptor MakeSecurityDescriptor();
    }


}
