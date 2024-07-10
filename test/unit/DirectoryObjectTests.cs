using System.Collections.Generic;
using System.Security.Principal;
using CommonLibTest.Facades;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using Xunit;

namespace CommonLibTest
{
    public class DirectoryObjectTests
    {
        [Fact]
        public void Test_GetLabelIssuanceOIDObjects()
        {
            var attribs = new Dictionary<string, object>
            {
                { LDAPProperties.ObjectClass, new[]{"msPKI-Enterprise-Oid"} },
                { LDAPProperties.Flags, "2" }
            };

            var mock = new MockDirectoryObject("CN=Test,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration",
                attribs, "S-1-5-21-3130019616-2776909439-2417379446-500", "", Label.Base);

            var success = mock.GetLabel(out var label);
            Assert.True(success);
            Assert.Equal(Label.IssuancePolicy, label);

            mock = new MockDirectoryObject("CN=OID,CN=Public Key Services,CN=Services,CN=Configuration",
                attribs, "S-1-5-21-3130019616-2776909439-2417379446-500", "", Label.Base);
            success = mock.GetLabel(out label);
            Assert.True(success);
            Assert.Equal(Label.Container, label);
        }
    }
}