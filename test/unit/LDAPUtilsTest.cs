using System;
using Xunit;
using FluentAssertions;
using Xbehave;
using System.Security.Cryptography;
using CommonLib;
using CommonLibTest.Mock;
using System.DirectoryServices.Protocols;

namespace CommonLibTest
{
    public class MockConsole: ICliConsoleFacade {
        public void WriteLine(string message) {
            Console.WriteLine(message);
        }
    }

    public class LDAPUtilsTest : IDisposable
    {
        #region Private Members
        private ICliConsoleFacade _console;

        public CliBaseClient<string> _client;
        #endregion

        #region Contructor(s)

        public LDAPUtilsTest()
        {
            // This runs once per test.
            _console = new MockConsole();
            _client = new MockClient(_console);
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
            //_client.Main("--domain \"ldap.formsys.com\" --ldappassword \"password\" --ldapusername \"uid=tesla,dc=example,dc=com\"");
            Assert.True(true);

        }

        #region Creation
            
        /// <summary>
        /// Returns a string representation of an object.
        /// </summary>
        [Fact]
        public void CreateLdapConfig_WhenPassedNullDomain_NoException() {
            LDAPUtils _test = LDAPUtils.Instance;
            Assert.NotNull(_test);

        }

        #endregion

        #region Structural

        #endregion


        #region Behavioral

        #endregion

    }
}