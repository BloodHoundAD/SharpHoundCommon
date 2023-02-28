using System;
using System.Collections.Generic;
using System.Security.Principal;
using SharpHoundRPC;
using SharpHoundRPC.Shared;
using SharpHoundRPC.Wrappers;

namespace CommonLibTest.Facades.LSAMocks.DCMocks
{
    public class MockDCLSAPolicy : ILSAPolicy
    {
        public Result<(string Name, string Sid)> GetLocalDomainInformation()
        {
            return ("TESTLAB", Consts.MockDCMachineSid);
        }

        public Result<IEnumerable<SecurityIdentifier>> GetPrincipalsWithPrivilege(string userRight)
        {
            throw new NotImplementedException();
        }

        public Result<IEnumerable<(SecurityIdentifier sid, string Name, SharedEnums.SidNameUse Use, string Domain)>>
            GetResolvedPrincipalsWithPrivilege(string userRight)
        {
            return new List<(SecurityIdentifier sid, string Name, SharedEnums.SidNameUse Use, string Domain)>
            {
                (new SecurityIdentifier("S-1-5-32-544"), "Administrators", SharedEnums.SidNameUse.Alias, "abc")
            };
        }

        public Result<(string Name, SharedEnums.SidNameUse Use, string Domains)> LookupSid(SecurityIdentifier sid)
        {
            throw new NotImplementedException();
        }

        public Result<IEnumerable<(SecurityIdentifier Sid, string Name, SharedEnums.SidNameUse Use, string Domain)>>
            LookupSids(SecurityIdentifier[] sids)
        {
            throw new NotImplementedException();
        }
    }
}