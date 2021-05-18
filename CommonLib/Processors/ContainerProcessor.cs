using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using SharpHoundCommonLib.LDAPQueries;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib.Processors
{
    public class ContainerProcessor
    {
        /// <summary>
        /// Finds all immediate child objects of a container. 
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public static IEnumerable<TypedPrincipal> GetContainerChildObjects(SearchResultEntry entry)
        {
            var filter = new LDAPFilter().AddComputers().AddUsers().AddGroups().AddOUs().AddContainers();
            foreach (var childEntry in LDAPUtils.QueryLDAP(filter.GetFilter(), SearchScope.OneLevel,
                CommonProperties.ObjectID, Helpers.DistinguishedNameToDomain(entry.DistinguishedName), adsPath: entry.DistinguishedName))
            {
                var dn = childEntry.DistinguishedName.ToUpper();
                
                if (dn.Contains("CN=SYSTEM") || dn.Contains("CN=POLICIES") || dn.Contains("CN=PROGRAM DATA"))
                    continue;

                var id = childEntry.GetObjectIdentifier();
                if (id == null)
                    continue;

                var res = LDAPUtils.ResolveIDAndType(id, Helpers.DistinguishedNameToDomain(childEntry.DistinguishedName));
                if (res == null)
                    continue;
                yield return res;
            }
        }

        /// <summary>
        /// Reads the "gplink" property from a SearchResult and converts the links into the acceptable SharpHound format
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public static IEnumerable<GPLink> ReadContainerGPLinks(SearchResultEntry entry)
        {
            var gpLinkProp = entry.GetProperty("gplink");
            if (gpLinkProp == null)
                yield break;

            foreach (var link in Helpers.SplitGPLinkProperty(gpLinkProp))
            {
                var enforced = link.Status.Equals("2");

                var res = LDAPUtils.ResolveDistinguishedName(link.DistinguishedName);
                    
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
        /// <param name="entry"></param>
        /// <returns></returns>
        public static bool ReadBlocksInheritance(SearchResultEntry entry)
        {
            var opts = entry.GetProperty("gpoptions");
            return opts is "1";
        }
    }
}