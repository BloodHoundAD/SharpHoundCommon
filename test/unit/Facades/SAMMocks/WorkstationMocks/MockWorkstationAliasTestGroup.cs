using System.Collections.Generic;
using System.Security.Principal;
using SharpHoundRPC;
using SharpHoundRPC.Wrappers;

namespace CommonLibTest.Facades
{
    public class MockWorkstationAliasTestGroup : ISAMAlias
    {
        public Result<IEnumerable<SecurityIdentifier>> GetMembers()
        {
            return new List<SecurityIdentifier>();
        }

        public void Dispose()
        {
            throw new System.NotImplementedException();
        }
    }
}