using System;

namespace SharpHoundCommonLib.Exceptions
{
    internal class NoLdapDataException : Exception {
        public NoLdapDataException(): base("No data returned")
        {
        }
    }
}