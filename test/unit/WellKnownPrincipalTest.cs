using System;
using System.DirectoryServices.ActiveDirectory;
using Moq;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using Xunit;

namespace CommonLibTest
{
    public class WellKnownPrincipalTest : IDisposable
    {
        #region Private Members

        #endregion

        #region Constructor(s)

        public WellKnownPrincipalTest()
        {

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
            var mock = new Mock<Forest>();
            mock.Setup(x => x.Name).Returns("PARENT.LOCAL");
            var mock2 = new Mock<LDAPUtils>();
            mock2.Setup(x => x.GetForest(null)).Returns(mock.Object);

            var result = WellKnownPrincipal.GetWellKnownPrincipal("S-1-5-9", null, out var typedPrincipal);
            Assert.True(result);
            Assert.Equal("PARENT.LOCAL-S-1-5-9", typedPrincipal.ObjectIdentifier);
            Assert.Equal(Label.Group, typedPrincipal.ObjectType);
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
