using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using CommonLib;
using CommonLib.Enums;
using CommonLib.Output;
using CommonLibTest.Mock;
using Xunit;
using Domain = System.DirectoryServices.ActiveDirectory.Domain;

namespace CommonLibTest
{
    public class WellKnownPrincipalTest : IDisposable
    {
        #region Private Members
        private ICliConsoleFacade _console;

        public CliBaseClient<string> _client;
        #endregion

        #region Contructor(s)

        public WellKnownPrincipalTest()
        {
            // This runs once per test.
            _console = new MockConsole();
            _client = new MockClient(_console);
        }

        #endregion

        #region Tests

        /// <summary>
        /// Test the GetWellKnownPrincipal for sid: 'S-1-0-0'
        /// </summary>
        [Fact]
        public void GetWellKnownPrincipal_PassingTestSid__ReturnsValidTypedPrincipal()
        {
            TypedPrincipal typedPrincipal;

            bool result = WellKnownPrincipal.GetWellKnownPrincipal("S-1-0-0", out typedPrincipal);

            Assert.True(result);
            Assert.Equal(Label.User, typedPrincipal.ObjectType);
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
