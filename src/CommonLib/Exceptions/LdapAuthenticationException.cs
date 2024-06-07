using System;
using System.DirectoryServices.Protocols;

namespace SharpHoundCommonLib.Exceptions
{
    public class LdapAuthenticationException : Exception
    {
        public readonly LdapException LdapException;
        public LdapAuthenticationException(LdapException exception) : base("Error authenticating to LDAP", exception)
        {
            LdapException = exception;
        }
    }
}