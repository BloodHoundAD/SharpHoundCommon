using System;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest
{
    public class LDAPUtilsTest : IDisposable
    {
        private readonly ITestOutputHelper _testOutputHelper;

        #region Private Members

        #endregion

        #region Constructor(s)

        public LDAPUtilsTest(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
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

        #region Creation
            
        /// <summary>
        /// 
        /// </summary>
        [Fact]
        public void GetUserGlobalCatalogMatches_Garbage_ReturnsNull() {
            var test = LDAPUtils.Instance.GetUserGlobalCatalogMatches("foo");
            _testOutputHelper.WriteLine(test.ToString());
            Assert.NotNull(test);
            Assert.Empty(test);
        }

        [Fact]
        public void ResolveIDAndType_DuplicateSid_ReturnsNull()
        {
            var test = LDAPUtils.Instance.ResolveIDAndType("ABC0ACNF", null);
            Assert.Null(test);
        }

        [Fact]
        public void ResolveIDAndType_WellKnownAdministrators_ReturnsConvertedSID()
        {
            var test = LDAPUtils.Instance.ResolveIDAndType("S-1-5-32-544", "TESTLAB.LOCAL");
            Assert.NotNull(test);
            Assert.Equal(Label.Group, test.ObjectType);
            Assert.Equal("TESTLAB.LOCAL-S-1-5-32-544", test.ObjectIdentifier);
        }

        #endregion

        #region Structural

        #endregion


        #region Behavioral

        #endregion

    }
}