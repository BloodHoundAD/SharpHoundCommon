using System;
using System.Collections.Generic;
using System.Linq;
using FluentResults;
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

        public Result<(string Name, SharedEnums.SidNameUse Type)> LookupUserByRid(int rid)
        {
            var ridArray = new[] {rid};
            var status = SAMMethods.SamLookupIdsInDomain(Handle, 1, ridArray, out var namePointer, out var usePointer);
            if (status.IsError())
            {
                return Result.Fail($"SAMLookupIdsInDomain returned {status}");
            }

            return (namePointer.GetData<SharedStructs.UnicodeString>().ToString(), (SharedEnums.SidNameUse)usePointer.GetData<int>());
        }

        public Result<IEnumerable<(string Name, int Rid)>> GetAliases()
        {
            var enumerationContext = 0;
            var status = SAMMethods.SamEnumerateAliasesInDomain(Handle, ref enumerationContext, out var ridPointer ,-1,
                out var count);
            if (status.IsError())
            {
                return Result.Fail($"SAMEnumerateAliasesInDomain returned {status}");
            }

            return Result.Ok(ridPointer.GetEnumerable<SAMStructs.SamRidEnumeration>(count)
                .Select(x => (x.Name.ToString(), x.Rid)));
        }

        public Result<SAMAlias> OpenAlias(int rid, SAMEnums.AliasOpenFlags desiredAccess = SAMEnums.AliasOpenFlags.ListMembers)
        {
            var status = SAMMethods.SamOpenAlias(Handle, desiredAccess, rid, out var aliasHandle);
            if (status.IsError())
            {
                return Result.Fail($"SAMOpenAlias returned {status}");
            }

            return new SAMAlias(aliasHandle);
        }

        public Result<SAMAlias> OpenAlias(string name)
        {
            var getAliasesResult = GetAliases();
            if (getAliasesResult.IsFailed)
            {
                return Result.Fail(getAliasesResult.Errors.First());
            }
            foreach (var alias in getAliasesResult.Value)
                if (alias.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                    return OpenAlias(alias.Rid);

            return Result.Fail($"Alias {name} was not found");
        }
    }
}