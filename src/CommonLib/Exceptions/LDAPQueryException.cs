using System;

namespace SharpHoundCommonLib.Exceptions
{
    public class LDAPQueryException : Exception
    {
        public LDAPQueryException()
        {
        }

        public LDAPQueryException(string message) : base(message)
        {
        }

        public LDAPQueryException(string message, Exception inner) : base(message, inner)
        {
        }
    }
}