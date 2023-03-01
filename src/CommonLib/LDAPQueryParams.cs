using System.DirectoryServices.Protocols;
using SharpHoundCommonLib.Exceptions;

namespace SharpHoundCommonLib
{
    internal class LDAPQueryParams
    {
        public LdapConnection Connection { get; set; }
        public SearchRequest SearchRequest { get; set; }
        public PageResultRequestControl PageControl { get; set; }
        public LDAPQueryException Exception { get; set; }
    }
}

