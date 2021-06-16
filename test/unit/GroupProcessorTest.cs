using System.Linq;
using CommonLibTest.Facades;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.Processors;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest
{
    public class GroupProcessorTest
    {
        private readonly ITestOutputHelper _testOutputHelper;
        private GroupProcessor _baseProcessor;
        private readonly string _testDomainName;

        private readonly string[] _testMembership = {
            "CN=Domain Admins,CN=Users,DC=testlab,DC=local",
            "CN=Enterprise Admins,CN=Users,DC=testlab,DC=local",
            "CN=Administrator,CN=Users,DC=testlab,DC=local"
        };
        
        public GroupProcessorTest(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
            _testDomainName = "TESTLAB.LOCAL";
            _baseProcessor = new GroupProcessor(new LDAPUtils());
        }

        [Fact]
        public void GroupProcessor_GetPrimaryGroupInfo_NullPrimaryGroupID_ReturnsNull()
        {
            var result = GroupProcessor.GetPrimaryGroupInfo(null, null);
            Assert.Null(result);
        }

        [WindowsOnlyFact]
        public void GroupProcessor_GetPrimaryGroupInfo_ReturnsCorrectSID()
        {
            var result = GroupProcessor.GetPrimaryGroupInfo("513", "S-1-5-21-3130019616-2776909439-2417379446-1105");
            Assert.Equal("S-1-5-21-3130019616-2776909439-2417379446-513", result);
        }

        [Fact]
        public void GroupProcessor_GetPrimaryGroupInfo_BadSID_ReturnsNull()
        {
            var result = GroupProcessor.GetPrimaryGroupInfo("513", "ABC123");
            Assert.Null(result);
        }

        [WindowsOnlyFact]
        public void GroupProcessor_GetGroupInformation_ReturnsCorrectMembers()
        {
            var utils = new MockLDAPUtils();
            var processor = new GroupProcessor(utils);
            var expected = new TypedPrincipal[]
            {
                new()
                {
                     ObjectIdentifier = "S-1-5-21-3130019616-2776909439-2417379446-512",
                     ObjectType = Label.Group
                },
                new()
                {
                    ObjectIdentifier = "S-1-5-21-3130019616-2776909439-2417379446-519",
                    ObjectType = Label.Group
                },
                new()
                {
                    ObjectIdentifier = "S-1-5-21-3130019616-2776909439-2417379446-500",
                    ObjectType = Label.User
                }
            };
            
            var results = processor.ReadGroupMembers("CN=Administrators,CN=Builtin,DC=testlab,DC=local", _testMembership).ToArray();
            foreach (var t in results)
            {
                _testOutputHelper.WriteLine(t.ToString());
            }
            Assert.Equal(3, results.Length);
            Assert.Equal(expected, results);
        }
    }
}
