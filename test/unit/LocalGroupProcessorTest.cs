using System;
using System.Linq;
using System.Threading.Tasks;
using CommonLibTest.Facades;
using Moq;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.Processors;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest
{
    public class LocalGroupProcessorTest : IDisposable
    {
        private readonly ITestOutputHelper _testOutputHelper;

        public LocalGroupProcessorTest(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        public void Dispose()
        {
        }

        [WindowsOnlyFact]
        public async Task LocalGroupProcessor_TestWorkstation()
        {
            var mockProcessor = new Mock<LocalGroupProcessor>(new MockLDAPUtils(), null);
            var mockSamServer = new MockWorkstationSAMServer();
            mockProcessor.Setup(x => x.OpenSamServer(It.IsAny<string>())).Returns(mockSamServer);
            var processor = mockProcessor.Object;
            var machineDomainSid = $"{Consts.MockWorkstationMachineSid}-1001";
            var results = await processor.GetLocalGroups("win10.testlab.local", machineDomainSid, "TESTLAB.LOCAL", false)
                .ToArrayAsync();

            Assert.Equal(3, results.Length);
            var adminGroup = results.First(x => x.ObjectIdentifier.EndsWith("-544"));
            Assert.Single(adminGroup.Results);
            Assert.Equal($"{machineDomainSid}-544", adminGroup.ObjectIdentifier);
            Assert.Equal("S-1-5-21-4243161961-3815211218-2888324771-512", adminGroup.Results[0].ObjectIdentifier);
            var rdpGroup = results.First(x => x.ObjectIdentifier.EndsWith("-555"));
            Assert.Equal(2, rdpGroup.Results.Length);
            Assert.Collection(rdpGroup.Results, 
                principal =>
                {
                    Assert.Equal($"{machineDomainSid}-1003", principal.ObjectIdentifier);
                    Assert.Equal(Label.LocalGroup, principal.ObjectType);
                    
                }, principal =>
                {
                    Assert.Equal($"{machineDomainSid}-544", principal.ObjectIdentifier);
                    Assert.Equal(Label.LocalGroup, principal.ObjectType);
                });
        }

        [WindowsOnlyFact]
        public async Task LocalGroupProcessor_TestDomainController()
        {
            var mockProcessor = new Mock<LocalGroupProcessor>(new MockLDAPUtils(), null);
            var mockSamServer = new MockDCSAMServer();
            mockProcessor.Setup(x => x.OpenSamServer(It.IsAny<string>())).Returns(mockSamServer);
            var processor = mockProcessor.Object;
            var machineDomainSid = $"{Consts.MockWorkstationMachineSid}-1000";
            var results = await processor.GetLocalGroups("primary.testlab.local", machineDomainSid, "TESTLAB.LOCAL", true)
                .ToArrayAsync();

            Assert.Equal(2, results.Length);
            var adminGroup = results.First(x => x.ObjectIdentifier.EndsWith("-544"));
            Assert.Single(adminGroup.Results);
            Assert.Equal("TESTLAB.LOCAL-S-1-5-32-544", adminGroup.ObjectIdentifier);
            Assert.Equal("S-1-5-21-4243161961-3815211218-2888324771-512", adminGroup.Results[0].ObjectIdentifier);
        }

        [Fact]
        public async Task LocalGroupProcessor_ResolveGroupName_NonDC()
        {
            var mockUtils = new Mock<MockLDAPUtils>();
            var proc = new LocalGroupProcessor(mockUtils.Object);

            var result = TestPrivateMethod.InstanceMethod<NamedPrincipal>(proc, "ResolveGroupName",
                new object[]
                {
                    "ADMINISTRATORS", "WIN10.TESTLAB.LOCAL", "S-1-5-32-123-123-500", "TESTLAB.LOCAL", 544, false, false
                });

            Assert.Equal("ADMINISTRATORS@WIN10.TESTLAB.LOCAL", result.PrincipalName);
            ;
            Assert.Equal("S-1-5-32-123-123-500-544", result.ObjectId);
        }

        [Fact]
        public async Task LocalGroupProcessor_ResolveGroupName_DC()
        {
            var mockUtils = new Mock<MockLDAPUtils>();
            var proc = new LocalGroupProcessor(mockUtils.Object);

            var result = TestPrivateMethod.InstanceMethod<NamedPrincipal>(proc, "ResolveGroupName",
                new object[]
                {
                    "ADMINISTRATORS", "PRIMARY.TESTLAB.LOCAL", "S-1-5-32-123-123-1000", "TESTLAB.LOCAL", 544, true, true
                });

            Assert.Equal("IGNOREME", result.PrincipalName);
            ;
            Assert.Equal("TESTLAB.LOCAL-S-1-5-32-544", result.ObjectId);
        }
    }
}