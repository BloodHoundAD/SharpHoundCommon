using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib.Processors
{
    public class SPNProcessors
    {
        private const string MSSQLSPNString = "mssqlsvc";
        private readonly ILogger _log;
        private readonly ILDAPUtils _utils;

        public SPNProcessors(ILDAPUtils utils, ILogger log = null)
        {
            _utils = utils;
            _log = log ?? Logging.LogProvider.CreateLogger("SPNProc");
        }

        public IAsyncEnumerable<SPNTarget> ReadSPNTargets(ResolvedSearchResult result,
            ISearchResultEntry entry)
        {
            var members = entry.GetArrayProperty("member");
            var name = result.DisplayName;
            var dn = entry.DistinguishedName;

            return ReadSPNTargets(members, dn, name);
        }

        public IAsyncEnumerable<SPNTarget> ReadSPNTargets(string[] servicePrincipalNames,
            string distinguishedName)
        {
            return ReadSPNTargets(servicePrincipalNames, distinguishedName, string.Empty);
        }

        public async IAsyncEnumerable<SPNTarget> ReadSPNTargets(string[] servicePrincipalNames,
            string distinguishedName, string objectName)
        {
            if (servicePrincipalNames.Length == 0)
            {
                _log.LogTrace("SPN Array is empty for {name}", objectName);
                yield break;
            }

            var domain = Helpers.DistinguishedNameToDomain(distinguishedName);

            foreach (var spn in servicePrincipalNames)
            {
                //This SPN format isn't useful for us right now (username@domain)
                if (spn.Contains("@"))
                {
                    _log.LogTrace("Skipping spn without @ {spn} for {name}", spn, objectName);
                    continue;
                }

                _log.LogTrace("Processing SPN {spn} for {name}", spn, objectName);

                if (spn.ToLower().Contains(MSSQLSPNString))
                {
                    _log.LogTrace("Matched SQL SPN {spn} for {name}", spn, objectName);
                    var port = 1433;

                    if (spn.Contains(":"))
                        if (!int.TryParse(spn.Split(':')[1], out port))
                            port = 1433;

                    var host = await _utils.ResolveHostToSid(spn, domain);
                    _log.LogTrace("Resolved {spn} to {host}", spn, host);
                    if (host.StartsWith("S-1-"))
                        yield return new SPNTarget
                        {
                            ComputerSID = host,
                            Port = port,
                            Service = SPNService.MSSQL
                        };
                }
            }
        }
    }
}