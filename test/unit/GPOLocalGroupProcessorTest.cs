using System.Data.Common;
using System.Runtime.InteropServices;
using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Moq;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.Processors;
using SharpHoundCommonLib.LDAPQueries;
using Xunit;
using Xunit.Abstractions;
using System.DirectoryServices.Protocols;
using System.Collections.Generic;

namespace CommonLibTest
{


    public class GPOLocalGroupProcessorTest
    {
        private ITestOutputHelper _testOutputHelper;
        public GPOLocalGroupProcessorTest(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }


        string GroupXmlContent = @"<?xml version=""1.0"" encoding=""UTF-8""?>
        <Groups clsid=""{3125E937-EB16-4b4c-9934-544FC6D24D26}"">
            <Group clsid=""{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}"" uid=""{49951410-3929-4041-AB49-75404B3BBB8A}"" changed=""2019-10-30 00:07:18"" image=""2"" name=""Administrators"">
                <Properties groupName=""Administrators"" groupSid="""" removeAccounts=""0"" deleteAllGroups=""0"" deleteAllUsers=""0"" description="""" newName="""" action=""U"">
                    <Members>
                        <Member name=""TESTLAB\Domain Users"" action=""ADD"" sid=""S-1-5-21-3130019616-2776909439-2417379446-513""/>
                        <Member name=""TESTLAB\Domain Computers"" action=""ADD"" sid=""S-1-5-21-3130019616-2776909439-2417379446-515""/>
                    </Members>
                </Properties>
            </Group>
        </Groups>";

        string GroupXmlContent2 = @"<?xml version=""1.0"" encoding=""UTF-8""?>
        <Groups clsid=""{3125E937-EB16-4b4c-9934-544FC6D24D26}"">
            <Group clsid=""{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}"" uid=""{D8BF17B2-92AA-4CFC-825C-707E15A10C89}"" changed=""2019-10-30 00:04:02"" image=""2"" name=""Administrators"">
                <Properties groupName=""Administrators"" groupSid="""" removeAccounts=""0"" deleteAllGroups=""0"" deleteAllUsers=""0"" description="""" newName="""" action=""U"">
                    <Members>
                        <Member name=""TESTLAB\Domain Admins"" action=""ADD"" sid=""S-1-5-21-3130019616-2776909439-2417379446-512""/>
                        <Member name=""TESTLAB\dfm"" action=""ADD"" sid=""S-1-5-21-3130019616-2776909439-2417379446-1105""/>
                        <Member name=""TESTLAB\Domain Computers"" action=""ADD"" sid=""S-1-5-21-3130019616-2776909439-2417379446-515""/>
                    </Members>
                </Properties>
            </Group>
        </Groups>
        ";

        string gpttmplInfContent = @"[Unicode]
        Unicode=yes
        [Version]
        signature=""$CHICAGO$""
        Revision=1
        [Group Membership]
        *S-1-5-21-3130019616-2776909439-2417379446-514__Memberof = *S-1-5-32-544
        *S-1-5-21-3130019616-2776909439-2417379446-514__Members =
        ";

        [Fact(Skip = "")]
        public async Task GPOLocalGroupProcessor_ReadGPOLocalGroups_Null_GPLink()
        {
            var mockLDAPUtils = new Mock<ILDAPUtils>();
            var processor = new GPOLocalGroupProcessor(mockLDAPUtils.Object);

            var result = await processor.ReadGPOLocalGroups(null, null);
            Assert.Null(result);
        }

        [Fact(Skip = "")]
        public async Task GPOLocalGroupProcessor_ReadGPOLocalGroups_AffectedComputers_0()
        {
            var mockLDAPUtils = new Mock<ILDAPUtils>();
            mockLDAPUtils.Setup(x => x.QueryLDAP(
                It.IsAny<string>(),
                It.IsAny<SearchScope>(),
                It.IsAny<string[]>(),
                It.IsAny<CancellationToken>(),
                It.IsAny<string>(),
                It.IsAny<bool>(),
                It.IsAny<bool>(),
                It.IsAny<string>(),
                It.IsAny<bool>(),
                It.IsAny<bool>()
            )).Returns(new List<ISearchResultEntry>());
            var processor = new GPOLocalGroupProcessor(mockLDAPUtils.Object);

            var result = await processor.ReadGPOLocalGroups("teapot", null);
            Assert.Null(result);
        }

        [Fact(Skip = "")]
        public async Task GPOLocalGroupProcessor_ReadGPOLocalGroups_Null_Gpcfilesyspath()
        {
            var mockLDAPUtils = new Mock<ILDAPUtils>();
            var mockSearchResultEntry = new Mock<ISearchResultEntry>();
            mockSearchResultEntry.Setup(x => x.GetSid()).Returns("teapot");
            var mockSearchResults = new List<ISearchResultEntry>();
            mockSearchResults.Add(mockSearchResultEntry.Object);
            mockLDAPUtils.Setup(x => x.QueryLDAP(new LDAPQueryOptions
            {
                filter = "(samaccounttype=805306369)",
                scope = SearchScope.Subtree,
                properties = CommonProperties.ObjectSID,
                adsPath = null
            }))
            .Returns(mockSearchResults.ToArray());

            var processor = new GPOLocalGroupProcessor(mockLDAPUtils.Object);
            var testGPLinkProperty = "[LDAP:/o=foo/ou=foo Group (ABC123)/cn=foouser (blah)123/dc=somedomain;0;][LDAP:/o=foo/ou=foo Group (ABC123)/cn=foouser (blah)123/dc=someotherdomain;2;]";
            var result = await processor.ReadGPOLocalGroups(testGPLinkProperty, null);

            Assert.NotNull(result);
            Assert.Single(result.AffectedComputers);
            var actual = result.AffectedComputers.First();
            Assert.Equal(Label.Computer, actual.ObjectType);
            Assert.Equal("teapot", actual.ObjectIdentifier);
        }

        [Fact]
        public async Task GPOLocalGroupProcessor_ReadGPOLocalGroups()
        {
            var mockLDAPUtils = new Mock<ILDAPUtils>(MockBehavior.Strict);
            var gpcFileSysPath = Path.GetTempPath();

            var groupsXmlPath = Path.Join(gpcFileSysPath, "MACHINE", "Preferences", "Groups", "Groups.xml");

            Path.GetDirectoryName(groupsXmlPath);
            Directory.CreateDirectory(Path.GetDirectoryName(groupsXmlPath));
            File.WriteAllText(groupsXmlPath, GroupXmlContent);

            var mockComputerEntry = new Mock<ISearchResultEntry>();
            mockComputerEntry.Setup(x => x.GetSid()).Returns("teapot");
            var mockComputerResults = new List<ISearchResultEntry>();
            mockComputerResults.Add(mockComputerEntry.Object);

            var mockGCPFileSysPathEntry = new Mock<ISearchResultEntry>();
            mockGCPFileSysPathEntry.Setup(x => x.GetProperty(It.IsAny<string>())).Returns(gpcFileSysPath);
            var mockGCPFileSysPathResults = new List<ISearchResultEntry>();
            mockGCPFileSysPathResults.Add(mockGCPFileSysPathEntry.Object);

            mockLDAPUtils.SetupSequence(x => x.QueryLDAP(It.IsAny<LDAPQueryOptions>()))
                .Returns(mockComputerResults.ToArray())
                .Returns(mockGCPFileSysPathResults.ToArray());

            var processor = new GPOLocalGroupProcessor(mockLDAPUtils.Object);

            var testGPLinkProperty = "[LDAP:/o=foo/ou=foo Group (ABC123)/cn=foouser (blah)123/dc=somedomain;0;][LDAP:/o=foo/ou=foo Group (ABC123)/cn=foouser (blah)123/dc=someotherdomain;2;]";
            var result = await processor.ReadGPOLocalGroups(testGPLinkProperty, null);

            mockLDAPUtils.VerifyAll();
            Assert.NotNull(result);
            // Assert.Single(result.AffectedComputers);
            // var actual = result.AffectedComputers.First();
            // Assert.Equal(Label.Computer, actual.ObjectType);
            // Assert.Equal("teapot", actual.ObjectIdentifier);
        }
    }
}
