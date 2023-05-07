using System;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Threading;
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
        private readonly ILDAPUtils _utils;

        #region Constructor(s)

        public LDAPUtilsTest(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
            _testForestName = "PARENT.LOCAL";
            _testDomainName = "TESTLAB.LOCAL";
            _utils = new LDAPUtils();
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

        #region Private Members

        #endregion

        #region Creation

        /// <summary>
        /// </summary>
        [Fact]
        public void GetUserGlobalCatalogMatches_Garbage_ReturnsNull()
        {
            var test = _utils.GetUserGlobalCatalogMatches("foo");
            _testOutputHelper.WriteLine(test.ToString());
            Assert.NotNull(test);
            Assert.Empty(test);
        }

        [Fact]
        public void ResolveIDAndType_DuplicateSid_ReturnsNull()
        {
            var test = _utils.ResolveIDAndType("ABC0ACNF", null);
            Assert.Null(test);
        }

        [Fact]
        public void ResolveIDAndType_WellKnownAdministrators_ReturnsConvertedSID()
        {
            var test = _utils.ResolveIDAndType("S-1-5-32-544", "TESTLAB.LOCAL");
            Assert.NotNull(test);
            Assert.Equal(Label.Group, test.ObjectType);
            Assert.Equal("TESTLAB.LOCAL-S-1-5-32-544", test.ObjectIdentifier);
        }

        [WindowsOnlyFact]
        public void GetWellKnownPrincipal_EnterpriseDomainControllers_ReturnsCorrectedSID()
        {
            var mock = new Mock<LDAPUtils>();
            var mockForest = MockableForest.Construct(_testForestName);
            mock.Setup(x => x.GetForest(It.IsAny<string>())).Returns(mockForest);
            var result = mock.Object.GetWellKnownPrincipal("S-1-5-9", null, out var typedPrincipal);
            Assert.True(result);
            Assert.Equal($"{_testForestName}-S-1-5-9", typedPrincipal.ObjectIdentifier);
            Assert.Equal(Label.Group, typedPrincipal.ObjectType);
        }

        [Fact]
        public void GetWellKnownPrincipal_NonWellKnown_ReturnsNull()
        {
            var result = _utils.GetWellKnownPrincipal("S-1-5-21-123456-78910", _testDomainName, out var typedPrincipal);
            Assert.False(result);
            Assert.Null(typedPrincipal);
        }

        [Fact]
        public void GetWellKnownPrincipal_WithDomain_ConvertsSID()
        {
            var result =
                _utils.GetWellKnownPrincipal("S-1-5-32-544", _testDomainName, out var typedPrincipal);
            Assert.True(result);
            Assert.Equal(Label.Group, typedPrincipal.ObjectType);
            Assert.Equal($"{_testDomainName}-S-1-5-32-544", typedPrincipal.ObjectIdentifier);
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
        public void GetDomainRangeSize_BadDomain_ReturnsDefault()
        {
            var mock = new Mock<LDAPUtils>();
            mock.Setup(x => x.GetDomain(It.IsAny<string>())).Returns((Domain) null);
            var result = mock.Object.GetDomainRangeSize();
            Assert.Equal(750, result);
        }

        [Fact]
        public void GetDomainRangeSize_RespectsDefaultParam()
        {
            var mock = new Mock<LDAPUtils>();
            mock.Setup(x => x.GetDomain(It.IsAny<string>())).Returns((Domain) null);

            var result = mock.Object.GetDomainRangeSize(null, 1000);
            Assert.Equal(1000, result);
        }

        [Fact]
        public void GetDomainRangeSize_NoLdapEntry_ReturnsDefault()
        {
            var mock = new Mock<LDAPUtils>();
            var mockDomain = MockableDomain.Construct("testlab.local");
            mock.Setup(x => x.GetDomain(It.IsAny<string>())).Returns(mockDomain);
            mock.Setup(x => x.QueryLDAP(It.IsAny<string>(), It.IsAny<SearchScope>(), It.IsAny<string[]>(),
                It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<string>(), It.IsAny<bool>(),
                It.IsAny<bool>(), It.IsAny<bool>())).Returns(new List<ISearchResultEntry>());

            var result = mock.Object.GetDomainRangeSize();
            Assert.Equal(750, result);
        }

        [Fact]
        public void GetDomainRangeSize_ExpectedResults()
        {
            var mock = new Mock<LDAPUtils>();
            var mockDomain = MockableDomain.Construct("testlab.local");
            mock.Setup(x => x.GetDomain(It.IsAny<string>())).Returns(mockDomain);
            var searchResult = new MockSearchResultEntry("CN=Default Query Policy,CN=Query-Policies,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=testlab,DC=local", new Dictionary<string, object>
            {
                {"ldapadminlimits", new[]
                {
                    "MaxPageSize=1250"
                }},
            }, "abc123", Label.Base);
            
            mock.Setup(x => x.QueryLDAP(It.IsAny<string>(), It.IsAny<SearchScope>(), null,
                It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<string>(), It.IsAny<bool>(),
                It.IsAny<bool>(), It.IsAny<bool>())).Returns(new List<ISearchResultEntry> {searchResult});
            var result = mock.Object.GetDomainRangeSize();
            Assert.Equal(1250, result);
        }

        [Fact]
        public void DistinguishedNameToDomain_DeletedObjects_CorrectDomain()
        {
            var result = SharpHoundCommonLib.Helpers.DistinguishedNameToDomain(
                @"DC=..Deleted-_msdcs.testlab.local\0ADEL:af1f072f-28d7-4b86-9b87-a408bfc9cb0d,CN=Deleted Objects,DC=testlab,DC=local");
            Assert.Equal("TESTLAB.LOCAL", result);
        }

        [Fact]
        public void QueryLDAP_With_Exception()
        {
            var options = new LDAPQueryOptions
            {
                ThrowException = true
            };

            Assert.Throws<LDAPQueryException>(
                () =>
                {
                    foreach (var sre in _utils.QueryLDAP(null, new SearchScope(), null, new CancellationToken(), null,
                                 false, false, null, false, false, true))
                    {
                        // We shouldn't reach this anyway, and all we care about is if exceptions are bubbling
                    }
                });

            Assert.Throws<LDAPQueryException>(
                () =>
                {
                    foreach (var sre in _utils.QueryLDAP(options))
                    {
                        // We shouldn't reach this anyway, and all we care about is if exceptions are bubbling
                    }
                });
        }

        [Fact]
        public void QueryLDAP_Without_Exception()
        {
            Exception exception;

            var options = new LDAPQueryOptions
            {
                ThrowException = false
            };

            exception = Record.Exception(
                () =>
                {
                    foreach (var sre in _utils.QueryLDAP(null, new SearchScope(), null, new CancellationToken()))
                    {
                        // We shouldn't reach this anyway, and all we care about is if exceptions are bubbling
                    }
                });
            Assert.Null(exception);

            exception = Record.Exception(
                () =>
                {
                    foreach (var sre in _utils.QueryLDAP(options))
                    {
                        // We shouldn't reach this anyway, and all we care about is if exceptions are bubbling
                    }
                });
            Assert.Null(exception);
        }

        #endregion

        #region Structural

        #endregion


        #region Behavioral

        #endregion
    }
}