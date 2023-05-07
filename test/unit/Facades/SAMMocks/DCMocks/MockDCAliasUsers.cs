﻿using System.Collections.Generic;
using System.Security.Principal;
using SharpHoundRPC;
using SharpHoundRPC.Wrappers;

namespace CommonLibTest.Facades
{
    public class MockDCAliasUsers : ISAMAlias
    {
        public Result<IEnumerable<SecurityIdentifier>> GetMembers()
        {
            return new List<SecurityIdentifier>
            {
                new("S-1-5-4"),
                new("S-1-5-11"),
                new("S-1-5-21-4243161961-3815211218-2888324771-513"),
            };
        }

        public void Dispose()
        {
            throw new System.NotImplementedException();
        }
    }
}