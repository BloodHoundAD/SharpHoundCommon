using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using SharpHoundRPC.Handles;
using SharpHoundRPC.LSANative;
using SharpHoundRPC.Shared;

namespace SharpHoundRPC.Wrappers
{
    public class LSAPolicy : LSABase
    {
        private string _computerName;

        public LSAPolicy(string computerName, LSAHandle handle) : base(handle)
        {
            _computerName = computerName;
        }

        public static Result<LSAPolicy> OpenPolicy(string computerName, LSAEnums.LsaOpenMask desiredAccess =
            LSAEnums.LsaOpenMask.LookupNames | LSAEnums.LsaOpenMask.ViewLocalInfo)
        {
            var (status, handle) = LSAMethods.LsaOpenPolicy(computerName, desiredAccess);
            if (status.IsError()) return status;

            return new LSAPolicy(computerName, handle);
        }

        public Result<(string Name, string Sid)> GetLocalDomainInformation()
        {
            var result = LSAMethods.LsaQueryInformationPolicy(Handle,
                LSAEnums.LSAPolicyInformation.PolicyAccountDomainInformation);

            if (result.status.IsError()) return result.status;

            var domainInfo = result.pointer.GetData<LSAStructs.PolicyAccountDomainInfo>();
            var domainSid = new SecurityIdentifier(domainInfo.DomainSid);
            return (domainInfo.DomainName.ToString(), domainSid.Value.ToUpper());
        }

        public Result<IEnumerable<SecurityIdentifier>> GetPrincipalsWithPrivilege(string userRight)
        {
            var (status, sids, count) = LSAMethods.LsaEnumerateAccountsWithUserRight(Handle, userRight);
            if (status.IsError()) return status;

            return Result<IEnumerable<SecurityIdentifier>>.Ok(sids.GetEnumerable<SecurityIdentifier>(count));
        }

        public Result<IEnumerable<(SecurityIdentifier sid, string Name, SharedEnums.SidNameUse Use, string Domain)>>
            GetResolvedPrincipalsWithPrivilege(string userRight)
        {
            var (status, sids, count) = LSAMethods.LsaEnumerateAccountsWithUserRight(Handle, userRight);
            if (status.IsError()) return status;

            var (lookupStatus, referencedDomains, names, lookupCount) = LSAMethods.LsaLookupSids(Handle, sids, count);
            var translatedNames = names.GetEnumerable<LSAStructs.LSATranslatedNames>(count).ToArray();
            var domainList = referencedDomains.GetData<LSAStructs.LSAReferencedDomains>();
            var safeDomains = new LSAPointer(domainList.Domains);
            var domains = safeDomains.GetEnumerable<LSAStructs.LSATrustInformation>(domainList.Entries).ToArray();
            var convertedSids = sids.GetEnumerable<SecurityIdentifier>(count).ToArray();

            var ret = new List<(SecurityIdentifier sid, string Name, SharedEnums.SidNameUse Use, string Domain)>();
            for (var i = 0; i < count; i++)
                ret.Add((convertedSids[i], translatedNames[i].Name.ToString(), translatedNames[i].Use,
                    domains[translatedNames[i].DomainIndex].Name.ToString()));

            return ret;
        }

        public Result<(string Name, SharedEnums.SidNameUse Use, string Domains)> LookupSid(SecurityIdentifier sid)
        {
            if (sid == null)
                return "SID cannot be null";

            var (status, referencedDomains, names, count) = LSAMethods.LsaLookupSids(Handle, new[] {sid});
            if (status.IsError()) return status;

            var translatedNames = names.GetEnumerable<LSAStructs.LSATranslatedNames>(count).ToArray();
            var domainList = referencedDomains.GetData<LSAStructs.LSAReferencedDomains>();
            var safeDomains = new LSAPointer(domainList.Domains);
            var domains = safeDomains.GetEnumerable<LSAStructs.LSATrustInformation>(domainList.Entries).ToArray();
            return (translatedNames[0].Name.ToString(), translatedNames[0].Use,
                domains[translatedNames[0].DomainIndex].Name.ToString());
        }

        public Result<IEnumerable<(SecurityIdentifier Sid, string Name, SharedEnums.SidNameUse Use, string Domain)>>
            LookupSids(
                SecurityIdentifier[] sids)
        {
            sids = sids.Where(x => x != null).ToArray();
            if (sids.Length == 0)
                return "No non-null SIDs specified";

            var (status, referencedDomains, names, count) = LSAMethods.LsaLookupSids(Handle, sids);
            if (status.IsError()) return status;

            var translatedNames = names.GetEnumerable<LSAStructs.LSATranslatedNames>(count).ToArray();
            var domainList = referencedDomains.GetData<LSAStructs.LSAReferencedDomains>();
            var safeDomains = new LSAPointer(domainList.Domains);
            var domains = safeDomains.GetEnumerable<LSAStructs.LSATrustInformation>(domainList.Entries).ToArray();

            var ret = new List<(SecurityIdentifier Sid, string Name, SharedEnums.SidNameUse Use, string Domain)>();
            for (var i = 0; i < count; i++)
                ret.Add((sids[i], translatedNames[i].Name.ToString(), translatedNames[i].Use,
                    domains[translatedNames[i].DomainIndex].Name.ToString()));

            return ret.ToArray();
        }
    }
}