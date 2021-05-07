using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using CommonLib.LDAPQuery;

namespace CommonLib.Output
{
    public class ContainerProcessors
    {
        public static async IAsyncEnumerable<TypedPrincipal> GetContainerChildObjects(SearchResultEntry entry)
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

        public static async IAsyncEnumerable<GPLink> ReadContainerGPLinks(SearchResultEntry entry)
        {
            var gpLinkProp = entry.GetProperty("gplink");
            if (gpLinkProp == null)
                yield break;
            
            foreach (var link in gpLinkProp.Split(']', '[').Where(x => x.StartsWith("LDAP")))
            {
                var s = link.Split(';');
                var dn = s[0].Substring(s[0].IndexOf("CN=", StringComparison.OrdinalIgnoreCase));
                var status = s[1];
                    
                // 1 and 3 represent Disabled, Not Enforced and Disabled, Enforced respectively.
                if (status is "3" or "1")
                    continue;

                var enforced = status.Equals("2");

                var res = await LDAPUtils.ResolveDistinguishedName(dn);
                    
                if (res == null)
                    continue;

                yield return new GPLink
                {
                    GUID = res.ObjectIdentifier,
                    IsEnforced = enforced
                };
            }
        }
        
        public static bool ReadBlocksInheritance(SearchResultEntry entry)
        {
            var opts = entry.GetProperty("gpoptions");
            return opts is "1";
        }
    }
}