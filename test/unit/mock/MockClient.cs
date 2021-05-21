using System;
using Xunit;
using FluentAssertions;
using Xbehave;
using System.Security.Cryptography;
using CommonLib;
using System.Threading.Tasks;

namespace CommonLibTest.Mock 
{
    public class MockClient : CliBaseClient<string>
    {
        public MockClient(ICliConsoleFacade console) : base(console)
        {
            
        }

        public override Task Start<T>(Options<T> options)
        {
            throw new NotImplementedException();
        }
    }
}