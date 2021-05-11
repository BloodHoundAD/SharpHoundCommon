using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using CommonLib.Output;

namespace CommonLib.LDAPQuery
{
    public class SPNProcessors
    {
        public static async IAsyncEnumerable<SPNTarget> ReadSPNTargets(SearchResultEntry entry)
        {
            var spns = entry.GetPropertyAsArray("serviceprincipalname");
            if (spns.Length == 0)
                yield break;

            var domain = Helpers.DistinguishedNameToDomain(entry.DistinguishedName);

            foreach (var spn in spns)
            {
                //This SPN format isn't useful for us right now (username@domain)
                if (spn.Contains("@"))
                    continue;

                if (spn.ToLower().Contains("mssqlsvc"))
                {
                    var port = 1433;

                    if (spn.Contains(":"))
                    {
                        if (!int.TryParse(spn.Split(':')[1], out port))
                        {
                            port = 1433;
                        }
                    }
                    var host = await LDAPUtils.ResolveHostToSid(spn, domain);
                    if (host.StartsWith("S-1-"))
                    {
                        yield return new SPNTarget
                        {
                            ComputerSID = host,
                            Port = port,
                            Service = SPNService.MSSQl
                        };
                    }
                }
            }
        }
    }
}