using System;
using System.Collections.Generic;
using System.Linq;
using SharpHoundRPC.Handles;
using SharpHoundRPC.SAMRPCNative;
using SharpHoundRPC.Shared;

namespace SharpHoundRPC.Wrappers
{
    public class SAMDomain : SAMBase, ISAMDomain
    {
        public SAMDomain(SAMHandle handle) : base(handle)
        {
        }

        public Result<(string Name, SharedEnums.SidNameUse Type)> LookupPrincipalByRid(int rid)
        {
            var (status, namePointer, usePointer) = SAMMethods.SamLookupIdsInDomain(Handle, rid);
            
            if (status.IsError()) return status;

            return (namePointer.GetData<SharedStructs.UnicodeString>().ToString(),
                (SharedEnums.SidNameUse) usePointer.GetData<int>());
        }

        public Result<IEnumerable<(string Name, int Rid)>> GetAliases()
        {
            var (status, ridPointer, count) = SAMMethods.SamEnumerateAliasesInDomain(Handle);

            if (status.IsError())
            {
                return status;
            }

            var ret = Result<IEnumerable<(string Name, int Rid)>>.Ok(ridPointer
                .GetEnumerable<SAMStructs.SamRidEnumeration>(count)
                .Select(x => (x.Name.ToString(), x.Rid)));
            
            return ret;
        }

        public Result<ISAMAlias> OpenAlias(int rid,
            SAMEnums.AliasOpenFlags desiredAccess = SAMEnums.AliasOpenFlags.ListMembers)
        {
            var (status, aliasHandle) = SAMMethods.SamOpenAlias(Handle, desiredAccess, rid);
            if (status.IsError()) return status;

            return new SAMAlias(aliasHandle);
        }

        public Result<ISAMAlias> OpenAlias(string name)
        {
            var getAliasesResult = GetAliases();
            if (getAliasesResult.IsFailed) return getAliasesResult.Status;

            foreach (var alias in getAliasesResult.Value)
                if (alias.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                    return OpenAlias(alias.Rid);

            return $"Alias {name} was not found";
        }
    }
}