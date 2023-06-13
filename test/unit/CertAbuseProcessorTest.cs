using System;
using System.DirectoryServices;
using CommonLibTest.Facades;
using Moq;
using Newtonsoft.Json;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.Processors;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest
{
    public class CertAbuseProcessorTest : IDisposable
    {
        private const string CASecurityFixture =
            "AQAUhCABAAAwAQAAFAAAAEQAAAACADAAAgAAAALAFAD//wAAAQEAAAAAAAEAAAAAAsAUAP//AAABAQAAAAAABQcAAAACANwABwAAAAADGAABAAAAAQIAAAAAAAUgAAAAIAIAAAADGAACAAAAAQIAAAAAAAUgAAAAIAIAAAADJAABAAAAAQUAAAAAAAUVAAAAIE+Qun9GhKV2SBaQAAIAAAADJAACAAAAAQUAAAAAAAUVAAAAIE+Qun9GhKV2SBaQAAIAAAADJAABAAAAAQUAAAAAAAUVAAAAIE+Qun9GhKV2SBaQBwIAAAADJAACAAAAAQUAAAAAAAUVAAAAIE+Qun9GhKV2SBaQBwIAAAADFAAAAgAAAQEAAAAAAAULAAAAAQIAAAAAAAUgAAAAIAIAAAECAAAAAAAFIAAAACACAAA=";

        private readonly ITestOutputHelper _testOutputHelper;

        public CertAbuseProcessorTest(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        public void Dispose()
        {
        }

        // [Fact]
        // public void CertAbuseProcessor_GetTrustedCerts_EmptyForNonRoot()
        // {
        //     var mockUtils = new Mock<MockLDAPUtils>();
        //     mockUtils.Setup(x => x.IsForestRoot(It.IsAny<string>())).Returns(false);
        //     var processor = new CertAbuseProcessor(mockUtils.Object);
        //
        //     var results = processor.GetTrustedCerts("testlab.local");
        //     Assert.Empty(results);
        // }
        //
        // [Fact]
        // public void CertAbuseProcessor_GetTrustedCerts_NullConfigPath_ReturnsEmpty()
        // {
        //     var mockUtils = new Mock<MockLDAPUtils>();
        //     mockUtils.Setup(x => x.IsForestRoot(It.IsAny<string>())).Returns(true);
        //     mockUtils.Setup(x => x.GetConfigurationPath(It.IsAny<string>())).Returns((string)null);
        //     var processor = new CertAbuseProcessor(mockUtils.Object);
        //
        //     var results = processor.GetTrustedCerts("testlab.local");
        //     Assert.Empty(results);
        // }
        //
        // [Fact]
        // public void CertAbuseProcessor_GetRootCAs_EmptyForNonRoot()
        // {
        //     var mockUtils = new Mock<MockLDAPUtils>();
        //     mockUtils.Setup(x => x.IsForestRoot(It.IsAny<string>())).Returns(false);
        //     var processor = new CertAbuseProcessor(mockUtils.Object);
        //
        //     var results = processor.GetRootCAs("testlab.local");
        //     Assert.Empty(results);
        // }
        //
        // [Fact]
        // public void CertAbuseProcessor_GetRootCAs_NullConfigPath_ReturnsEmpty()
        // {
        //     var mockUtils = new Mock<MockLDAPUtils>();
        //     mockUtils.Setup(x => x.IsForestRoot(It.IsAny<string>())).Returns(true);
        //     mockUtils.Setup(x => x.GetConfigurationPath(It.IsAny<string>())).Returns((string)null);
        //     var processor = new CertAbuseProcessor(mockUtils.Object);
        //
        //     var results = processor.GetRootCAs("testlab.local");
        //     Assert.Empty(results);
        // }

        [Fact]
        public void CertAbuseProcessor_ProcessCAPermissions_NullSecurity_ReturnsNull()
        {
            var mockUtils = new Mock<MockLDAPUtils>();
            var processor = new CertAbuseProcessor(mockUtils.Object);

            var results = processor.ProcessEnrollmentServicePermissions(null, null, "test", false);

            Assert.Empty(results);
        }

        // [WindowsOnlyFact]
        // public void CertAbuseProcessor_ProcessCAPermissions_ReturnsCorrectValues()
        // {
        //     var mockUtils = new Mock<MockLDAPUtils>();
        //     var sd = new ActiveDirectorySecurityDescriptor(new ActiveDirectorySecurity());
        //     mockUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(sd);
        //     var processor = new CertAbuseProcessor(mockUtils.Object);
        //     var bytes = Helpers.B64ToBytes(CASecurityFixture);

        //     var results = processor.ProcessCAPermissions(bytes, "TESTLAB.LOCAL", "test", false);
        //     _testOutputHelper.WriteLine(JsonConvert.SerializeObject(results, Formatting.Indented));
        //     Assert.Contains(results,
        //         x => x.RightName == EdgeNames.Owns && x.PrincipalSID == "TESTLAB.LOCAL-S-1-5-32-544" &&
        //              x.PrincipalType == Label.Group && !x.IsInherited);
        //     Assert.Contains(results,
        //         x => x.RightName == EdgeNames.Enroll && x.PrincipalSID == "TESTLAB.LOCAL-S-1-5-11" &&
        //              !x.IsInherited);
        //     Assert.Contains(results,
        //         x => x.RightName == EdgeNames.ManageCA && x.PrincipalSID == "TESTLAB.LOCAL-S-1-5-32-544" &&
        //              !x.IsInherited);
        //     Assert.Contains(results,
        //         x => x.RightName == EdgeNames.ManageCertificates && x.PrincipalSID == "TESTLAB.LOCAL-S-1-5-32-544" &&
        //              !x.IsInherited);
        //     Assert.Contains(results,
        //         x => x.RightName == EdgeNames.ManageCA &&
        //              x.PrincipalSID == "S-1-5-21-3130019616-2776909439-2417379446-512" &&
        //              !x.IsInherited);
        //     Assert.Contains(results,
        //         x => x.RightName == EdgeNames.ManageCertificates &&
        //              x.PrincipalSID == "S-1-5-21-3130019616-2776909439-2417379446-512" &&
        //              !x.IsInherited);
        //     Assert.Contains(results,
        //         x => x.RightName == EdgeNames.ManageCA &&
        //              x.PrincipalSID == "S-1-5-21-3130019616-2776909439-2417379446-519" &&
        //              !x.IsInherited);
        //     Assert.Contains(results,
        //         x => x.RightName == EdgeNames.ManageCertificates &&
        //              x.PrincipalSID == "S-1-5-21-3130019616-2776909439-2417379446-519" &&
        //              !x.IsInherited);
        // }
    }
}