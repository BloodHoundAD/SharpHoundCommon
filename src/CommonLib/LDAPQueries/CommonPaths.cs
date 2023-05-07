namespace SharpHoundCommonLib.LDAPQueries
{
    public static class CommonPaths
    {
        public const string QueryPolicyPath =
            "CN=Default Query Policy,CN=Query-Policies,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration";

        public const string ConfigurationPath = "CN=Configuration";

        public static string CreateDNPath(string prePath, string baseDomainDN)
        {
            return $"{prePath},{baseDomainDN}";
        }
    }
}

