using System.Collections.Generic;
using System.Security.Principal;

namespace SharpHoundRPC.Wrappers
{
    public interface ISAMAlias
    {
        Result<IEnumerable<SecurityIdentifier>> GetMembers();
    }
}