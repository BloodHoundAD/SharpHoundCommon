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

        public static LSAPolicy OpenPolicy(string computerName, LSAEnums.LsaOpenMask desiredAccess =
            LSAEnums.LsaOpenMask.LookupNames | LSAEnums.LsaOpenMask.ViewLocalInfo)
        {
            var handle = LSAMethods.LsaOpenPolicy(computerName, desiredAccess);
            return new LSAPolicy(computerName, handle);
        }

        public (string Name, string Sid) GetLocalDomainInformation()
        {
            var result = LSAMethods.LsaQueryInformationPolicy(Handle,
                LSAEnums.LSAPolicyInformation.PolicyAccountDomainInformation);

            var domainInfo = result.GetData<LSAStructs.PolicyAccountDomainInfo>();
            var domainSid = new SecurityIdentifier(domainInfo.DomainSid);
            return (domainInfo.DomainName.ToString(), domainSid.Value.ToUpper());
        }

        public IEnumerable<SecurityIdentifier> GetPrincipalsWithPrivilege(string userRight)
        {
            return LSAMethods.LsaEnumerateAccountsWithUserRight(Handle, userRight);
        }

        public (string Name, SharedEnums.SidNameUse Use, string Domains) LookupSid(SecurityIdentifier sid)
        {
            var result = LSAMethods.LsaLookupSids(Handle, new[] {sid}).First();
            return (result.Name, result.Use, result.Domain);
        }

        public IEnumerable<(SecurityIdentifier Sid, string Name, SharedEnums.SidNameUse Use, string Domain)> LookupSids(
            SecurityIdentifier[] sids)
        {
            return LSAMethods.LsaLookupSids(Handle, sids);
        }
    }
}