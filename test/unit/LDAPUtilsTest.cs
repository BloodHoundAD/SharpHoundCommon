using System;
using CommonLibTest.Facades;
using Moq;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.Exceptions;
using System.DirectoryServices.Protocols;
using System.Threading;
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
        public void QueryLDAP_With_Exception()
        {
            var options = new LDAPQueryOptions
            {
                ThrowException = true
            };

            Assert.Throws<SharpHoundCommonException>(
                () =>
                {
                    foreach (var sre in _utils.QueryLDAP(null, new SearchScope(), null, new CancellationToken(), null, false, false, null, false, false, true))
                    {
                        // We shouldn't reach this anyway, and all we care about is if exceptions are bubbling
                    };
                });

            Assert.Throws<SharpHoundCommonException>(
                () =>
                {
                    foreach (var sre in _utils.QueryLDAP(options))
                    {
                        // We shouldn't reach this anyway, and all we care about is if exceptions are bubbling
                    };
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
                    };
                });
            Assert.Null(exception);

            exception = Record.Exception(
                () =>
                {
                    foreach (var sre in _utils.QueryLDAP(options))
                    {
                        // We shouldn't reach this anyway, and all we care about is if exceptions are bubbling
                    };
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