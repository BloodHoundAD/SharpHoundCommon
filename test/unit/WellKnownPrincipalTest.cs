using System;
using System.Reflection;
using CommonLibTest.Facades;
using Moq;
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
        #endregion

        #region Constructor(s)

        public WellKnownPrincipalTest(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
            _testDomainName = "TESTLAB.LOCAL";
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
            var forest = MockableForest.Construct();
            var ldapUtilsMock = new Mock<ILDAPUtils>();
            ldapUtilsMock.Setup(x => x.GetForest(null)).Returns(forest);
            var lazyMock = new Lazy<ILDAPUtils>(() => ldapUtilsMock.Object);
            //Call this to ensure that static construction occurs
            var _ = LDAPUtils.Instance;
            var instance = typeof(LDAPUtils).GetField("lazy", BindingFlags.Static | BindingFlags.NonPublic);
            instance.SetValue(null, lazyMock);

            var result = WellKnownPrincipal.GetWellKnownPrincipal("S-1-5-9", null, out var typedPrincipal);
            Assert.True(result);
            Assert.Equal("PARENT.LOCAL-S-1-5-9", typedPrincipal.ObjectIdentifier);
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
            Assert.Equal("TESTLAB.LOCAL-S-1-5-32-544", typedPrincipal.ObjectIdentifier);
        }

        #endregion

        #region IDispose Implementation
        public void Dispose()
        {
            // Tear down (called once per test)
        }
        #endregion
    }
}
