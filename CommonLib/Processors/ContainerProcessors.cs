using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Threading.Tasks;

namespace CommonLib.Output
{
    public class ContainerProcessors
    {
        public static async Task<OUContainerData> ReadOUContainerData(SearchResultEntry entry)
        {
            var data = new OUContainerData();
            var domain = Helpers.DistinguishedNameToDomain(entry.DistinguishedName);

            var opts = entry.GetProperty("gpoptions");
            data.BlocksInheritance = opts is "1";

            var gpLinkProp = entry.GetProperty("gplink");
            var links = new List<GPLink>();
            if (gpLinkProp != null)
            {
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
                    
                    links.Add(new GPLink
                    {
                        GUID = res.ObjectIdentifier,
                        IsEnforced = enforced
                    });
                }

                data.Links = links.ToArray();
            }
            else
            {
                data.Links = new GPLink[0];
            }
        }
        
    }

    public class OUContainerData
    {
        public bool BlocksInheritance { get; set; }
        public TypedPrincipal[] ChildObjects { get; set; }
        public GPLink[] Links { get; set; }
    }
}