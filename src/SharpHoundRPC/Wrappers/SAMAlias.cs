using System.Collections.Generic;
using System.Security.Principal;
using SharpHoundRPC.Handles;
using SharpHoundRPC.SAMRPCNative;

namespace SharpHoundRPC.Wrappers
{
    public class SAMAlias : SAMBase, ISAMAlias
    {
        public SAMAlias(SAMHandle handle) : base(handle)
        {
        }

        public string Name { get; set; }
        public int Rid { get; set; }

        public Result<IEnumerable<SecurityIdentifier>> GetMembers()
        {
            var (status, members, count) = SAMMethods.SamGetMembersInAlias(Handle);

            if (status.IsError())
            {
                return status;
            } 
            
            return Result<IEnumerable<SecurityIdentifier>>.Ok(members.GetData(count));
        
        }
    }
}