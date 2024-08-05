using System;
using System.DirectoryServices.Protocols;

namespace SharpHoundCommonLib.Exceptions
{
    internal class LdapAuthenticationException : Exception
    {
        public readonly LdapException LdapException;
        public LdapAuthenticationException(LdapException exception) : base("Credentials are invalid for connection", exception)
        {
            LdapException = exception;
        }
    }
}