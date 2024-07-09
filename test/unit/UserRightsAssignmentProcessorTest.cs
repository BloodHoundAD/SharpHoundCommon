using System.Linq;
using System.Threading.Tasks;
using CommonLibTest.Facades;
using CommonLibTest.Facades.LSAMocks.DCMocks;
using CommonLibTest.Facades.LSAMocks.WorkstationMocks;
using Moq;
using Newtonsoft.Json;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.Processors;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest
{
    public class UserRightsAssignmentProcessorTest
    {
        private readonly ITestOutputHelper _testOutputHelper;

        public UserRightsAssignmentProcessorTest(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        [WindowsOnlyFact]
        public async Task UserRightsAssignmentProcessor_TestWorkstation()
        {
            var mockProcessor = new Mock<UserRightsAssignmentProcessor>(new MockLDAPUtils(), null);
            var mockLSAPolicy = new MockWorkstationLSAPolicy();
            mockProcessor.Setup(x => x.OpenLSAPolicy(It.IsAny<string>())).Returns(mockLSAPolicy);
            var processor = mockProcessor.Object;
            var machineDomainSid = $"{Consts.MockDomainSid}-1001";
            var results = await processor.GetUserRightsAssignments("win10.testlab.local", machineDomainSid, "testlab.local", false)
                    .ToArrayAsync();

            var privilege = results[0];
            Assert.Equal(LSAPrivileges.RemoteInteractiveLogon, privilege.Privilege);
            Assert.Equal(3, results[0].Results.Length);
            var adminResult = privilege.Results.First(x => x.ObjectIdentifier.EndsWith("-544"));
            Assert.Equal($"{machineDomainSid}-544", adminResult.ObjectIdentifier);
            Assert.Equal(Label.LocalGroup, adminResult.ObjectType);
            var rdpResult = privilege.Results.First(x => x.ObjectIdentifier.EndsWith("-555"));
            Assert.Equal($"{machineDomainSid}-555", rdpResult.ObjectIdentifier);
            Assert.Equal(Label.LocalGroup, rdpResult.ObjectType);
        }

        [WindowsOnlyFact]
        public async Task UserRightsAssignmentProcessor_TestDC()
        {
            var mockProcessor = new Mock<UserRightsAssignmentProcessor>(new MockLDAPUtils(), null);
            var mockLSAPolicy = new MockDCLSAPolicy();
            mockProcessor.Setup(x => x.OpenLSAPolicy(It.IsAny<string>())).Returns(mockLSAPolicy);
            var processor = mockProcessor.Object;
            var machineDomainSid = $"{Consts.MockDomainSid}-1000";
            var results = await processor.GetUserRightsAssignments("primary.testlab.local", machineDomainSid, "testlab.local", true)
                    .ToArrayAsync();

            var privilege = results[0];
            _testOutputHelper.WriteLine(JsonConvert.SerializeObject(privilege));
            Assert.Equal(LSAPrivileges.RemoteInteractiveLogon, privilege.Privilege);
            Assert.Single(results[0].Results);
            var adminResult = privilege.Results.First(x => x.ObjectIdentifier.EndsWith("-544"));
            Assert.Equal("TESTLAB.LOCAL-S-1-5-32-544", adminResult.ObjectIdentifier);
            Assert.Equal(Label.Group, adminResult.ObjectType);
        }
    }
}