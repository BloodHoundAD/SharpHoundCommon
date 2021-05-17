using System;
using System.DirectoryServices.Protocols;
using System.Threading.Tasks;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib.Processors
{
    public class ComputerAvailability
    {
        public static async Task<ComputerStatus> IsComputerAvailable(SearchResultEntry entry, ResolvedSearchResult resolvedSearchResult)
        {
            var operatingSystem = entry.GetProperty("operatingsystem");
            if (operatingSystem != null && !operatingSystem.StartsWith("Windows", StringComparison.OrdinalIgnoreCase))
                return new ComputerStatus
                {
                    Connectable = false,
                    Error = "NonWindowsOS"
                };

            var passwordLastSet = ConvertLdapTime(entry.GetProperty("pwdlastset"));
            var threshold = DateTime.Now.AddDays(-60).ToFileTimeUtc();

            if (passwordLastSet < threshold)
                return new ComputerStatus
                {
                    Connectable = false,
                    Error = "PwdLastSetOutOfRange"
                };

            if (!await Helpers.CheckPort(resolvedSearchResult.DisplayName))
                return new ComputerStatus
                {
                    Connectable = false,
                    Error = "PortNotOpen"
                };

            return new ComputerStatus
            {
                Connectable = true,
                Error = null
            };
        }
        
        private static long ConvertLdapTime(string ldapTime)
        {
            if (ldapTime == null)
                return -1;

            var time = long.Parse(ldapTime);
            return time;
        }
    }
}