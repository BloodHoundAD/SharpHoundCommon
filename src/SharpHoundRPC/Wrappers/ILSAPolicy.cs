using System.Collections.Generic;
using System.Security.Principal;
using SharpHoundRPC.Shared;

namespace SharpHoundRPC.Wrappers
{
    public interface ILSAPolicy
    {
        Result<(string Name, string Sid)> GetLocalDomainInformation();
        Result<IEnumerable<SecurityIdentifier>> GetPrincipalsWithPrivilege(string userRight);

        Result<IEnumerable<(SecurityIdentifier sid, string Name, SharedEnums.SidNameUse Use, string Domain)>>
            GetResolvedPrincipalsWithPrivilege(string userRight);

        Result<(string Name, SharedEnums.SidNameUse Use, string Domains)> LookupSid(SecurityIdentifier sid);

        Result<IEnumerable<(SecurityIdentifier Sid, string Name, SharedEnums.SidNameUse Use, string Domain)>>
            LookupSids(
                SecurityIdentifier[] sids);
    }
}