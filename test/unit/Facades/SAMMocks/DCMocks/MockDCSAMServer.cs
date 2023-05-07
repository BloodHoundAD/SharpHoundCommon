﻿using System;
using System.Collections.Generic;
using System.Security.Principal;
using SharpHoundRPC;
using SharpHoundRPC.SAMRPCNative;
using SharpHoundRPC.Shared;
using SharpHoundRPC.Wrappers;

namespace CommonLibTest.Facades
{
    public class MockDCSAMServer : ISAMServer
    {
        public bool IsNull { get; }
        public Result<IEnumerable<(string Name, int Rid)>> GetDomains()
        {
            var domains = new List<(string, int)>
            {
                ("BUILTIN", 1)
            };
            return domains;
        }

        public virtual Result<SecurityIdentifier> LookupDomain(string name)
        {
            throw new System.NotImplementedException();
        }

        public Result<SecurityIdentifier> GetMachineSid(string testName = null)
        {
            var securityIdentifier = new SecurityIdentifier(Consts.MockDCMachineSid);
            return Result<SecurityIdentifier>.Ok(securityIdentifier);
        }

        public Result<(string Name, SharedEnums.SidNameUse Type)> LookupPrincipalBySid(SecurityIdentifier securityIdentifier)
        {
            throw new System.NotImplementedException();
        }

        public Result<ISAMDomain> OpenDomain(string domainName,
            SAMEnums.DomainAccessMask requestedDomainAccess = SAMEnums.DomainAccessMask.ListAccounts | SAMEnums.DomainAccessMask.Lookup)
        {
            if (domainName.Equals("builtin", StringComparison.OrdinalIgnoreCase))
            {
                return new MockDCDomainBuiltIn();
            }

            throw new NotImplementedException();
        }

        public Result<ISAMDomain> OpenDomain(SecurityIdentifier securityIdentifier,
            SAMEnums.DomainAccessMask requestedDomainAccess = SAMEnums.DomainAccessMask.ListAccounts | SAMEnums.DomainAccessMask.Lookup)
        {
            throw new System.NotImplementedException();
        }
    }
}