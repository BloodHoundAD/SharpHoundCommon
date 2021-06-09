using System;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest
{
    public class WellKnownPrincipalTest : IDisposable
    {
        #region Private Members
        private readonly ITestOutputHelper _testOutputHelper;
        private readonly string _testDomainName;
        private readonly string _testForestName;
        #endregion

        #region Constructor(s)

        public WellKnownPrincipalTest(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
            _testDomainName = "TESTLAB.LOCAL";
            _testForestName = "FOREST.LOCAL";
        }

        #endregion

        #region Tests

        /// <summary>
        /// Test the GetWellKnownPrincipal for sid: 'S-1-0-0'
        /// </summary>
        [Fact]
        public void GetWellKnownPrincipal_PassingTestSid__ReturnsValidTypedPrincipal()
        {
            var result = WellKnownPrincipal.GetWellKnownPrincipal("S-1-0-0", out var typedPrincipal);

            Assert.True(result);
            Assert.Equal(Label.User, typedPrincipal.ObjectType);
        }

        [Fact]
        public void GetWellKnownPrincipal_EnterpriseDomainControllers_ReturnsCorrectedSID()
        {
            Helpers.SwapMockUtils();
            var result = WellKnownPrincipal.GetWellKnownPrincipal("S-1-5-9", null, out var typedPrincipal);
            Assert.True(result);
            Assert.Equal($"{_testForestName}-S-1-5-9", typedPrincipal.ObjectIdentifier);
            Assert.Equal(Label.Group, typedPrincipal.ObjectType);
        }

        [Fact]
        public void GetWellKnownPrincipal_NonWellKnown_ReturnsNull()
        {
            var result = WellKnownPrincipal.GetWellKnownPrincipal("S-1-5-21-123456-78910", _testDomainName, out var typedPrincipal);
            Assert.False(result);
            Assert.Null(typedPrincipal);
        }

        [Fact]
        public void GetWellKnownPrincipal_WithDomain_ConvertsSID()
        {
            var result =
                WellKnownPrincipal.GetWellKnownPrincipal("S-1-5-32-544", _testDomainName, out var typedPrincipal);
            Assert.True(result);
            Assert.Equal(Label.Group, typedPrincipal.ObjectType);
            Assert.Equal($"{_testDomainName}-S-1-5-32-544", typedPrincipal.ObjectIdentifier);
        }

        #endregion

        #region IDispose Implementation
        public void Dispose()
        {
            // Tear down (called once per test)
            Helpers.RestoreMockUtils();
        }
        #endregion
    }
}
