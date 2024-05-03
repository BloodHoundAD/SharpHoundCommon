using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;

namespace SharpHoundCommonLib
{
    public class DomainWrapper
    {
        public string DomainSID { get; set; }
        public string DomainFQDN { get; set; }
        public string DomainSearchBase { get; set; }
        public string DomainConfigurationPath { get; set; }
        public string DomainNetbiosName { get; set; }
    }
}