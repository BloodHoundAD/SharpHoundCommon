using System;
using System.Collections.Generic;
using SharpHoundRPC.Handles;
using SharpHoundRPC.SAMRPCNative;
using SharpHoundRPC.Shared;

namespace SharpHoundRPC.Wrappers
{
    public class SAMDomain : SAMBase
    {
        public SAMDomain(SAMHandle handle) : base(handle)
        {
        }

        public (string Name, SharedEnums.SidNameUse Type) LookupUserByRid(int rid)
        {
            return SAMMethods.SamLookupIdsInDomain(Handle, rid);
        }

        public IEnumerable<(string Name, int Rid)> GetAliases()
        {
            return SAMMethods.SamEnumerateAliasesInDomain(Handle);
        }

        public SAMAlias OpenAlias(int rid)
        {
            return SAMMethods.SamOpenAlias(Handle, rid);
        }

        public SAMAlias OpenAlias(string name)
        {
            foreach (var alias in GetAliases())
                if (alias.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                    return OpenAlias(alias.Rid);

            throw new RPCException(RPCException.OpenAlias, RPCException.AliasNotFound);
        }
    }
}