using System;
using System.DirectoryServices.Protocols;
using CommonLibTest.Facades;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using Xunit;

namespace ConnectionTest
{
    public class ConnectionTests
    {
        [Fact]
        public void TestConnectionHappyPath()
        {
            var connection = MockLdapConnection.Get(ResponseBehavior.HappyPath);
            var testResponse = connection.TestConnection();

            Assert.True(testResponse.Success);
            Assert.Null(testResponse.Exception);

            // TODO : check testResponse domain data properties
        }

        [Fact]
        public void TestConnectionNullResponse()
        {
            var connection = MockLdapConnection.Get(ResponseBehavior.NullResponse);
            var testResponse = connection.TestConnection();

            Assert.False(testResponse.Success);
            Assert.Null(testResponse.Exception);
            Assert.Throws<ObjectDisposedException>(() => connection.Bind());
        }

        // This happens when a Kerberos misconfiguration occurs
        [Fact]
        public void TestConnectionEmptyResponse()
        {
            var connection = MockLdapConnection.Get(ResponseBehavior.EmptyResponse);
            var testResponse = connection.TestConnection();

            Assert.False(testResponse.Success);
            Assert.IsType<LdapException>(testResponse.Exception);
            Assert.Equal((int)LdapErrorCodes.KerberosAuthType, testResponse.Exception.ErrorCode);
            Assert.Throws<ObjectDisposedException>(() => connection.Bind());
        }

        [Fact]
        public void TestConnectionThrowsLdapException()
        {
            var connection = MockLdapConnection.Get(ResponseBehavior.ThrowsLdapException);
            var testResponse = connection.TestConnection();

            Assert.False(testResponse.Success);
            Assert.IsType<LdapException>(testResponse.Exception);
            Assert.Throws<ObjectDisposedException>(() => connection.Bind());
        }
    }
}