using System;

namespace SharpHoundCommonLib.Exceptions
{
    public class SharpHoundCommonException : Exception
    {
        public SharpHoundCommonException() { }
        public SharpHoundCommonException(string message) : base(message) { }
        public SharpHoundCommonException(string message, Exception inner) : base(message, inner) { }
    }
}
