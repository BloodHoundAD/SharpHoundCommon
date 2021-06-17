using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using SharpHoundCommonLib.LDAPQueries;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib.Processors
{
    public class ContainerProcessor
    {
        private readonly ILDAPUtils _utils;
        public ContainerProcessor(ILDAPUtils utils)
        {
            _utils = utils;
        }

        private static bool IsDNFiltered(string distinguishedName)
        {
            var dn = distinguishedName.ToUpper();
            if (dn.Contains("CN=PROGRAM DATA,DC="))
            {
                return true;
            }

            if (dn.Contains("CN=SYSTEM,DC="))
            {
                return true;
            }

            return false;
        }
        
        /// <summary>
        /// Finds all immediate child objects of a container. 
        /// </summary>
        /// <param name="distinguishedName"></param>
        /// <returns></returns>
        public IEnumerable<TypedPrincipal> GetContainerChildObjects(string distinguishedName)
        {
            var filter = new LDAPFilter().AddComputers().AddUsers().AddGroups().AddOUs().AddContainers();
            foreach (var childEntry in _utils.QueryLDAP(filter.GetFilter(), SearchScope.OneLevel,
                CommonProperties.ObjectID, Helpers.DistinguishedNameToDomain(distinguishedName), adsPath: distinguishedName))
            {
                var dn = childEntry.DistinguishedName;
                if (IsDNFiltered(dn))
                    continue;

                var id = childEntry.GetObjectIdentifier();
                if (id == null)
                    continue;

                var res = _utils.ResolveIDAndType(id, Helpers.DistinguishedNameToDomain(dn));
                if (res == null)
                    continue;
                yield return res;
            }
        }

        /// <summary>
        /// Reads the "gplink" property from a SearchResult and converts the links into the acceptable SharpHound format
        /// </summary>
        /// <param name="gpLink"></param>
        /// <returns></returns>
        public IEnumerable<GPLink> ReadContainerGPLinks(string gpLink)
        {
            if (gpLink == null)
                yield break;

            foreach (var link in Helpers.SplitGPLinkProperty(gpLink))
            {
                var enforced = link.Status.Equals("2");

                var res = _utils.ResolveDistinguishedName(link.DistinguishedName);
                    
                if (res == null)
                    continue;

                yield return new GPLink
                {
                    GUID = res.ObjectIdentifier,
                    IsEnforced = enforced
                };
            }
        }
        
        /// <summary>
        /// Checks if a container blocks privilege inheritance
        /// </summary>
        /// <param name="gpOptions"></param>
        /// <returns></returns>
        public static bool ReadBlocksInheritance(string gpOptions)
        {
            return gpOptions is "1";
        }
    }
}