using System.Collections.Generic;
using System.Security.Principal;
using FluentResults;
using SharpHoundRPC.Handles;
using SharpHoundRPC.SAMRPCNative;

namespace SharpHoundRPC.Wrappers
{
    public class SAMAlias : SAMBase
    {
        public SAMAlias(SAMHandle handle) : base(handle)
        {
        }

        public string Name { get; set; }
        public int Rid { get; set; }

        public Result<IEnumerable<SecurityIdentifier>> GetMembers()
        {
            var status = SAMMethods.SamGetMembersInAlias(Handle, out var members, out var count);
            if (status.IsError())
            {
                return Result.Fail($"SAMGetMembersInAlias returned {status}");
            }
            
            return Result.Ok(members.GetData(count));
        }
    }
}