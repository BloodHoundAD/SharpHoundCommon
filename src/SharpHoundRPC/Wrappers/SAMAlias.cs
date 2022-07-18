using System.Collections.Generic;
using System.Security.Principal;
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

        public IEnumerable<SecurityIdentifier> GetMembers()
        {
            return SAMMethods.SamGetMembersInAlias(Handle);
        }
    }
}