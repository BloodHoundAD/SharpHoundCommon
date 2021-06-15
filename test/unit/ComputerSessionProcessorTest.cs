using System.Threading.Tasks;
using CommonLibTest.Facades;
using Moq;
using SharpHoundCommonLib;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.Processors;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest
{
    public class ComputerSessionProcessorTest
    {
        private readonly ITestOutputHelper _testOutputHelper;
        private readonly ILDAPUtils _utils;
        private readonly string _computerDomain;

        public ComputerSessionProcessorTest(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
            _utils = new LDAPUtils();
            _computerDomain = "TESTLAB.LOCAL";
        }

        [Fact]
        public async Task ComputerSessionProcessor_ReadUserSessionsPrivileged_FilteringWorks()
        {
            var mockNativeMethods = new Mock<NativeMethods>();
            const string samAccountName = "WIN10";
            const string computerSid = "S-1-5-21-3130019616-2776909439-2417379446-1104";
            //This is a sample response from a computer in a test environment. The duplicates are intentional
            var apiResults = new NativeMethods.WKSTA_USER_INFO_1[]
            {
                new()
                {
                    wkui1_logon_domain = "TESTLAB",
                    wkui1_logon_server = "PRIMARY",
                    wkui1_oth_domains = "",
                    wkui1_username = "dfm"
                },
                new()
                {
                    wkui1_logon_domain = "",
                    wkui1_logon_server = "PRIMARY",
                    wkui1_oth_domains = "",
                    wkui1_username = "Administrator"
                },
                new()
                {
                    wkui1_logon_domain = "TESTLAB",
                    wkui1_logon_server = "",
                    wkui1_oth_domains = "",
                    wkui1_username = "WIN10$"
                },
                new()
                {
                    wkui1_logon_domain = "TESTLAB",
                    wkui1_logon_server = "",
                    wkui1_oth_domains = "",
                    wkui1_username = "WIN10$"
                },
                new()
                {
                    wkui1_logon_domain = "TESTLAB",
                    wkui1_logon_server = "",
                    wkui1_oth_domains = "",
                    wkui1_username = "WIN10$"
                },
                new()
                {
                    wkui1_logon_domain = "TESTLAB",
                    wkui1_logon_server = "",
                    wkui1_oth_domains = "",
                    wkui1_username = "WIN10$"
                }
            };
            mockNativeMethods.Setup(x => x.CallNetWkstaUserEnum(It.IsAny<string>())).Returns(apiResults);

            var expected = new Session[]
            {
                new()
                {
                    ComputerSID = computerSid,
                    UserSID ="S-1-5-21-3130019616-2776909439-2417379446-1105" 
                },
                new()
                {
                    ComputerSID = computerSid,
                    UserSID ="S-1-5-21-3130019616-2776909439-2417379446-500" 
                }
            };
            
            var processor = new ComputerSessionProcessor(new MockLDAPUtils(), mockNativeMethods.Object);
            var test = await processor.ReadUserSessionsPrivileged("WIN10.TESTLAB.LOCAL", samAccountName, _computerDomain, computerSid);
            Assert.True(test.Collected);
            Assert.Equal(2, test.Results.Length);
            Assert.Equal(expected, test.Results);
        }
        
        #region IDispose Implementation
        public void Dispose()
        {
            // Tear down (called once per test)
        }
        #endregion
    }
}