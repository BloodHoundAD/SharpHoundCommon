using System;
using Xunit;
using FluentAssertions;
using Xbehave;
using System.Security.Cryptography;
using SharpHoundCommonLib;
using System.DirectoryServices.Protocols;

namespace CommonLibTest
{
    public class LDAPUtilsTest : IDisposable
    {
        #region Private Members

        #endregion

        #region Constructor(s)

        public LDAPUtilsTest()
        {
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
            var _test = LDAPUtils.GetUserGlobalCatalogMatches("foo");
            Console.WriteLine(_test);
            Assert.NotNull(_test);

        }

        #endregion

        #region Structural

        #endregion


        #region Behavioral

        #endregion

    }
}