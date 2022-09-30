using System;

namespace SharpHoundCommonLib.Exceptions
{
    public class ComputerAPIException : Exception
    {
        public ComputerAPIException()
        {
        }

        public ComputerAPIException(string apiCall, NativeMethods.NtStatus status)
        {
            Status = status.ToString();
            APICall = apiCall;
        }

        public string Status { get; set; }
        public string APICall { get; set; }

        public override string ToString()
        {
            return $"Call to {APICall} returned {Status}";
        }
    }
}