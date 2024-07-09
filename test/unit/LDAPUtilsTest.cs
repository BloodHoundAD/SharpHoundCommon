using System;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Threading;
using System.Threading.Tasks;
using CommonLibTest.Facades;
using Moq;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.Exceptions;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest
{
    public class LDAPUtilsTest : IDisposable
    {
        private readonly string _testDomainName;
        private readonly string _testForestName;
        private readonly ITestOutputHelper _testOutputHelper;
        private readonly ILdapUtils _utils;

        #region Constructor(s)

        public LDAPUtilsTest(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
            _testForestName = "PARENT.LOCAL";
            _testDomainName = "TESTLAB.LOCAL";
            _utils = new LdapUtils();
            // This runs once per test.
        }

        #endregion

        #region IDispose Implementation

        public void Dispose()
        {
            // Tear down (called once per test)
        }

        #endregion

        [Fact]
        public void SanityCheck()
        {
            Assert.True(true);
        }

        /// <summary>
        /// </summary>
        [Fact]
        public async Task GetUserGlobalCatalogMatches_Garbage_ReturnsNull()
        {
            var test = await _utils.GetGlobalCatalogMatches("foo", "bar");
            _testOutputHelper.WriteLine(test.ToString());
            Assert.True(test.Success);
            Assert.Empty(test.Sids);
        }

        [Fact]
        public void ResolveIDAndType_DuplicateSid_ReturnsNull()
        {
            var test = _utils.ResolveIDAndType("ABC0ACNF", null);
            Assert.Null(test);
        }

        [Fact]
        public async void ResolveIDAndType_WellKnownAdministrators_ReturnsConvertedSID()
        {
            var test = await _utils.ResolveIDAndType("S-1-5-32-544", "TESTLAB.LOCAL");
            Assert.True(test.Success);
            Assert.NotNull(test.Principal);
            Assert.Equal(Label.Group, test.Principal.ObjectType);
            Assert.Equal("TESTLAB.LOCAL-S-1-5-32-544", test.Principal.ObjectIdentifier);
        }

        [WindowsOnlyFact]
        public async void GetWellKnownPrincipal_EnterpriseDomainControllers_ReturnsCorrectedSID()
        {
            var mock = new Mock<LdapUtils>();
            var mockForest = MockableForest.Construct(_testForestName);
            mock.Setup(x => x.GetForest(It.IsAny<string>())).Returns(mockForest);
            var result = await mock.Object.GetWellKnownPrincipal("S-1-5-9", null);
            Assert.True(result.Success);
            Assert.Equal($"{_testForestName}-S-1-5-9", result.WellKnownPrincipal.ObjectIdentifier);
            Assert.Equal(Label.Group, result.WellKnownPrincipal.ObjectType);
        }

        [Fact]
        public void BuildLdapPath_BadDomain_ReturnsNull()
        {
            var mock = new Mock<LdapUtils>();
            //var mockDomain = MockableDomain.Construct("TESTLAB.LOCAL");
            mock.Setup(x => x.GetDomain(It.IsAny<string>()))
                .Returns((Domain)null);
            var result = mock.Object.BuildLdapPath("TEST", "ABC");
            Assert.Null(result);
        }

        [WindowsOnlyFact]
        public void BuildLdapPath_HappyPath()
        {
            var mock = new Mock<LdapUtils>();
            var mockDomain = MockableDomain.Construct("TESTLAB.LOCAL");
            mock.Setup(x => x.GetDomain(It.IsAny<string>()))
                .Returns(mockDomain);
            var result = mock.Object.BuildLdapPath(DirectoryPaths.PKILocation, "ABC");
            Assert.NotNull(result);
            Assert.Equal("CN=Public Key Services,CN=Services,CN=Configuration,DC=TESTLAB,DC=LOCAL", result);
        }

        [Fact]
        public async void GetWellKnownPrincipal_NonWellKnown_ReturnsNull()
        {
            var result = await _utils.GetWellKnownPrincipal("S-1-5-21-123456-78910", _testDomainName);
            Assert.False(result.Success);
            Assert.Null(result.WellKnownPrincipal);
        }

        [Fact]
        public async void GetWellKnownPrincipal_WithDomain_ConvertsSID()
        {
            var result =
                await _utils.GetWellKnownPrincipal("S-1-5-32-544", _testDomainName);
            Assert.True(result.Success);
            Assert.Equal(Label.Group, result.WellKnownPrincipal.ObjectType);
            Assert.Equal($"{_testDomainName}-S-1-5-32-544", result.WellKnownPrincipal.ObjectIdentifier);
        }

        [Fact]
        public void DistinguishedNameToDomain_RegularObject_CorrectDomain()
        {
            var result = SharpHoundCommonLib.Helpers.DistinguishedNameToDomain(
                "CN=Account Operators,CN=Builtin,DC=testlab,DC=local");
            Assert.Equal("TESTLAB.LOCAL", result);

            result = SharpHoundCommonLib.Helpers.DistinguishedNameToDomain("DC=testlab,DC=local");
            Assert.Equal("TESTLAB.LOCAL", result);
        }

        [Fact]
        public void DistinguishedNameToDomain_DeletedObjects_CorrectDomain()
        {
            var result = SharpHoundCommonLib.Helpers.DistinguishedNameToDomain(
                @"DC=..Deleted-_msdcs.testlab.local\0ADEL:af1f072f-28d7-4b86-9b87-a408bfc9cb0d,CN=Deleted Objects,DC=testlab,DC=local");
            Assert.Equal("TESTLAB.LOCAL", result);
        }
    }
}