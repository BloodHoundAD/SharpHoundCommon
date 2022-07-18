using System;

namespace SharpHoundRPC
{
    public class RPCException : Exception
    {
        public const string Connect = "SamConnect";
        public const string EnumerateDomains = "SamEnumerateDomainsInSamServer";
        public const string ServerNotInitialized = "Server Not Initialized";
        public const string OpenAlias = "SamOpenAlias";
        public const string OpenDomain = "SamOpenDomain";
        public const string AliasNotFound = "Alias Not Found";
        public const string DomainNotFound = "Domain Not Found";
        public const string LookupIds = "SamLookupIdsInDomain";
        public const string EnumerateAliases = "SamEnumerateAliasesInDomain";
        public const string GetAliasMembers = "SamGetMembersinAlias";
        public const string LookupDomain = "SamLookupDomainInSamServer";
        public const string GetMachineSid = "GetMachineSid";
        private readonly string APICall;
        private readonly string Status;

        public RPCException(string apiCall, NtStatus status)
        {
            APICall = apiCall;
            Status = status.ToString();
        }

        public RPCException(string apiCall, string status)
        {
            APICall = apiCall;
            Status = status;
        }

        public override string ToString()
        {
            return $"Call to {APICall} returned {Status}";
        }
    }
}