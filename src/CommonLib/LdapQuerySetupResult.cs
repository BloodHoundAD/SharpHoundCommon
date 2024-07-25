using System.DirectoryServices;
using System.DirectoryServices.Protocols;

namespace SharpHoundCommonLib {
    public class LdapQuerySetupResult {
        public LdapConnectionWrapper ConnectionWrapper { get; set; }
        public SearchRequest SearchRequest { get; set; }
        public string Server { get; set; }
        public bool Success { get; set; }
        public string Message { get; set; }
    }
}