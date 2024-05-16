using System.DirectoryServices.Protocols;

namespace SharpHoundCommonLib
{
    public class LdapConnectionWrapper
    {
        public string Server;
        public int Port;
        public LdapConnection Connection;
        public string Domain;
    }
}