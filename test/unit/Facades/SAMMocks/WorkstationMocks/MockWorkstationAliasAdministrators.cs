﻿using System.Collections.Generic;
using System.Security.Principal;
using SharpHoundRPC;
using SharpHoundRPC.Wrappers;

namespace CommonLibTest.Facades
{
    public class MockWorkstationAliasAdministrators : ISAMAlias
    {
        public Result<IEnumerable<SecurityIdentifier>> GetMembers()
        {
            return new List<SecurityIdentifier>()
            {
                new("S-1-5-21-321011808-3761883066-353627080-500"),
                new("S-1-5-21-321011808-3761883066-353627080-1000"),
                new("S-1-5-21-4243161961-3815211218-2888324771-512"),
            };
        }

        public void Dispose()
        {
            throw new System.NotImplementedException();
        }
    }
}