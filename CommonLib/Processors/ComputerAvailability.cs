using System;
using System.Threading.Tasks;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib.Processors
{
    public class ComputerAvailability
    {
        /// <summary>
        /// Checks if a computer is available for SharpHound enumeration using the following criteria:
        /// The "operatingsystem" LDAP attribute must contain the string "Windows"
        /// The "pwdlastset" LDAP attribute must be within 60 days of the current date.
        /// Port 445 must be open to allow API calls to succeed
        /// </summary>
        /// <param name="computerName">The computer to check availability for</param>
        /// <param name="operatingSystem">The LDAP operatingsystem attribute value</param>
        /// <param name="pwdLastSet">The LDAP pwdlastset attribute value</param>
        /// <returns>A <cref>ComputerStatus</cref> object that represents the availability of the computer</returns>
        public static async Task<ComputerStatus> IsComputerAvailable(string computerName, string operatingSystem, string pwdLastSet)
        {
            if (operatingSystem != null && !operatingSystem.StartsWith("Windows", StringComparison.OrdinalIgnoreCase))
                return new ComputerStatus
                {
                    Connectable = false,
                    Error = "NonWindowsOS"
                };

            var passwordLastSet = ConvertLdapTime(pwdLastSet);
            var threshold = DateTime.Now.AddDays(-60).ToFileTimeUtc();

            if (passwordLastSet < threshold)
                return new ComputerStatus
                {
                    Connectable = false,
                    Error = "PwdLastSetOutOfRange"
                };

            if (!await Helpers.CheckPort(computerName))
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
        
        /// <summary>
        /// Converts an LDAP time string into a long
        /// </summary>
        /// <param name="ldapTime"></param>
        /// <returns></returns>
        private static long ConvertLdapTime(string ldapTime)
        {
            if (ldapTime == null)
                return -1;

            var time = long.Parse(ldapTime);
            return time;
        }
    }
}