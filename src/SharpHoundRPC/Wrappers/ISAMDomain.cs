using System.Collections.Generic;
using SharpHoundRPC.SAMRPCNative;
using SharpHoundRPC.Shared;

namespace SharpHoundRPC.Wrappers
{
    public interface ISAMDomain
    {
        Result<(string Name, SharedEnums.SidNameUse Type)> LookupPrincipalByRid(int rid);
        Result<IEnumerable<(string Name, int Rid)>> GetAliases();

        Result<ISAMAlias> OpenAlias(int rid,
            SAMEnums.AliasOpenFlags desiredAccess = SAMEnums.AliasOpenFlags.ListMembers);

        Result<ISAMAlias> OpenAlias(string name);
    }
}