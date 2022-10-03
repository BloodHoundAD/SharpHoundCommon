namespace SharpHoundRPC.NetAPINative
{
    public class NetWkstaUserEnumResults
    {
        public NetWkstaUserEnumResults(string username, string domain)
        {
            LogonDomain = domain;
            Username = username;
        }

        public string LogonDomain { get; }
        public string Username { get; }
    }

    public class NetSessionEnumResults
    {
        public NetSessionEnumResults(string username, string cname)
        {
            Username = username;
            ComputerName = cname;
        }

        public string Username { get; }
        public string ComputerName { get; }
    }
}