using System;
using System.DirectoryServices.Protocols;
using CommonLibTest;
using CommonLibTest.Facades;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using Xunit;
using static SharpHoundCommonLib.LDAPUtils;

namespace ConnectionTest
{
    public class ConnectionTests
    {
        [Fact]
        public void TestConnectionHappyPath()
        {
            var connection = MockLdapConnection.Get(ResponseBehavior.HappyPath);
            var utils = new LDAPUtils();
            var testResponse = TestPrivateMethod.InstanceMethod<LdapConnectionTestResult>(utils, "TestConnection", new object[] { connection });

            Assert.True(testResponse.Success);
            Assert.Null(testResponse.Exception);

            // TODO : check testResponse domain data properties?
            // Not sure I should care about these implementation details tbh
            // might be breaking that logic out, make easier to Mock
            // tbd
        }

        [Fact]
        public void TestConnectionNullResponse()
        {
            var connection = MockLdapConnection.Get(ResponseBehavior.NullResponse);
            var utils = new LDAPUtils();
            var testResponse = TestPrivateMethod.InstanceMethod<LdapConnectionTestResult>(utils, "TestConnection", new object[] { connection });

            Assert.False(testResponse.Success);
            Assert.Null(testResponse.Exception);
            Assert.Throws<ObjectDisposedException>(() => connection.Bind());
        }

        // This happens when a Kerberos misconfiguration occurs
        [Fact]
        public void TestConnectionEmptyResponse()
        {
            var connection = MockLdapConnection.Get(ResponseBehavior.EmptyResponse);
            var utils = new LDAPUtils();
            var testResponse = TestPrivateMethod.InstanceMethod<LdapConnectionTestResult>(utils, "TestConnection", new object[] { connection });

            Assert.False(testResponse.Success);
            Assert.IsType<LdapException>(testResponse.Exception);
            Assert.Equal((int)LdapErrorCodes.KerberosAuthType, testResponse.Exception.ErrorCode);
            Assert.Throws<ObjectDisposedException>(() => connection.Bind());
        }

        [Fact]
        public void TestConnectionThrowsLdapException()
        {
            var connection = MockLdapConnection.Get(ResponseBehavior.ThrowsLdapException);
            var utils = new LDAPUtils();
            var testResponse = TestPrivateMethod.InstanceMethod<LdapConnectionTestResult>(utils, "TestConnection", new object[] { connection });

            Assert.False(testResponse.Success);
            Assert.IsType<LdapException>(testResponse.Exception);
            Assert.Throws<ObjectDisposedException>(() => connection.Bind());
        }

        [Fact]
        public void TestConnectionThrowsOtherException()
        {
            var connection = MockLdapConnection.Get(ResponseBehavior.ThrowsLdapException);
            var utils = new LDAPUtils();
            var testResponse = TestPrivateMethod.InstanceMethod<LdapConnectionTestResult>(utils, "TestConnection", new object[] { connection });

            // TODO : evaluate this behavior
            // currently in TestConnection we raise any non-ldap exception up
            // should we?
            Assert.False(testResponse.Success);
            Assert.NotNull(testResponse.Exception);
            Assert.Throws<ObjectDisposedException>(() => connection.Bind());
        }
    }
}