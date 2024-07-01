using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.LDAPQueries;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib.Processors
{
    public class ContainerProcessor
    {
        private readonly ILogger _log;
        private readonly ILdapUtilsNew _utils;

        public ContainerProcessor(ILdapUtilsNew utils, ILogger log = null)
        {
            _utils = utils;
            _log = log ?? Logging.LogProvider.CreateLogger("ContainerProc");
        }

        private static bool IsDistinguishedNameFiltered(string distinguishedName)
        {
            var dn = distinguishedName.ToUpper();
            if (dn.Contains("CN=PROGRAM DATA,DC=")) return true;

            if (dn.Contains("CN=SYSTEM,DC=")) return true;

            return false;
        }

        /// <summary>
        /// Helper function to pass commonlib types to GetContainingObject
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public async Task<(bool Success, TypedPrincipal principal)> GetContainingObject(ISearchResultEntry entry)
        {
            return await GetContainingObject(entry.DistinguishedName);
        }

        /// <summary>
        /// Uses the distinguishedname of an object to get its containing object by stripping the first part and using the remainder to find the container object
        /// Saves lots of LDAP calls compared to enumerating container info directly
        /// </summary>
        /// <param name="distinguishedName"></param>
        /// <returns></returns>
        public async Task<(bool Success, TypedPrincipal Principal)> GetContainingObject(string distinguishedName)
        {
            var containerDn = Helpers.RemoveDistinguishedNamePrefix(distinguishedName);

            if (containerDn.StartsWith("CN=BUILTIN", StringComparison.OrdinalIgnoreCase))
            {
                var domain = Helpers.DistinguishedNameToDomain(distinguishedName);
                var (success, domainSid) = await _utils.GetDomainSidFromDomainName(domain);
                if (success) {
                    return (true, new TypedPrincipal(domainSid, Label.Domain));    
                }

                return (false, default);
            }

            return await _utils.LookupDistinguishedName(containerDn);
        }

        /// <summary>
        ///     Helper function using commonlib types to pass to GetContainerChildObjects
        /// </summary>
        /// <param name="result"></param>
        /// <param name="entry"></param>
        /// <returns></returns>
        public IAsyncEnumerable<TypedPrincipal> GetContainerChildObjects(ResolvedSearchResult result,
            ISearchResultEntry entry)
        {
            var name = result.DisplayName;
            var dn = entry.DistinguishedName;

            return GetContainerChildObjects(dn, name);
        }

        /// <summary>
        ///     Finds all immediate child objects of a container.
        /// </summary>
        /// <param name="distinguishedName"></param>
        /// <param name="containerName"></param>
        /// <returns></returns>
        public async IAsyncEnumerable<TypedPrincipal> GetContainerChildObjects(string distinguishedName, string containerName = "")
        {
            var filter = new LDAPFilter().AddComputers().AddUsers().AddGroups().AddOUs().AddContainers();
            filter.AddCertificateAuthorities().AddCertificateTemplates().AddEnterpriseCertificationAuthorities();
            await foreach (var childEntryResult in _utils.Query(new LdapQueryParameters {
                               DomainName = Helpers.DistinguishedNameToDomain(distinguishedName),
                               SearchScope = SearchScope.OneLevel,
                               Attributes = CommonProperties.ObjectID,
                               LDAPFilter = filter.GetFilter(),
                               SearchBase = distinguishedName
                           })) {
                if (!childEntryResult.Success) {
                    _log.LogWarning("Error while getting container child objects for {DistinguishedName}: {Reason}", distinguishedName, childEntryResult.Error);
                    yield break;
                }

                var childEntry = childEntryResult.Value;
                var dn = childEntry.DistinguishedName;
                if (IsDistinguishedNameFiltered(dn))
                {
                    _log.LogTrace("Skipping filtered child {Child} for {Container}", dn, containerName);
                    continue;
                }

                var id = childEntry.GetObjectIdentifier();
                if (id == null)
                {
                    _log.LogTrace("Got null ID for {ChildDN} under {Container}", childEntry.DistinguishedName,
                        containerName);
                    continue;
                }

                var res = await _utils.ResolveIDAndType(id, Helpers.DistinguishedNameToDomain(dn));
                if (res.Success) {
                    yield return res.Principal;
                }
            }
        }

        public IAsyncEnumerable<GPLink> ReadContainerGPLinks(ResolvedSearchResult result, ISearchResultEntry entry)
        {
            var links = entry.GetProperty(LDAPProperties.GPLink);

            return ReadContainerGPLinks(links);
        }

        /// <summary>
        ///     Reads the "gplink" property from a SearchResult and converts the links into the acceptable SharpHound format
        /// </summary>
        /// <param name="gpLink"></param>
        /// <returns></returns>
        public async IAsyncEnumerable<GPLink> ReadContainerGPLinks(string gpLink)
        {
            if (gpLink == null)
                yield break;

            foreach (var link in Helpers.SplitGPLinkProperty(gpLink))
            {
                var enforced = link.Status.Equals("2");

                var res = await _utils.LookupDistinguishedName(link.DistinguishedName);

                if (res.Success) {
                    yield return new GPLink
                    {
                        GUID = res.Principal.ObjectIdentifier,
                        IsEnforced = enforced
                    };
                }
            }
        }

        /// <summary>
        ///     Checks if a container blocks privilege inheritance
        /// </summary>
        /// <param name="gpOptions"></param>
        /// <returns></returns>
        public static bool ReadBlocksInheritance(string gpOptions)
        {
            return gpOptions is "1";
        }
    }
}