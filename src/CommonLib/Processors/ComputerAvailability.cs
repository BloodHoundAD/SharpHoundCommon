using System;
using System.Threading.Tasks;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib.Processors
{
    public class ComputerAvailability
    {
        private PortScanner _scanner;

        public ComputerAvailability()
        {
            _scanner = new PortScanner();
        }

        public ComputerAvailability(PortScanner scanner)
        {
            _scanner = scanner;
        }
        
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
        public async Task<ComputerStatus> IsComputerAvailable(string computerName, string operatingSystem, string pwdLastSet)
        {
            if (operatingSystem != null && !operatingSystem.StartsWith("Windows", StringComparison.OrdinalIgnoreCase))
            {
                Logging.Trace($"{computerName} is not available because operating system does not match.");
                return new ComputerStatus
                {
                    Connectable = false,
                    Error = ComputerStatus.NonWindowsOS
                };
            }

            var passwordLastSet = Helpers.ConvertLdapTimeToLong(pwdLastSet);
            var threshold = DateTime.Now.AddDays(-60).ToFileTimeUtc();

            if (passwordLastSet < threshold)
            {
                Logging.Trace($"{computerName} is not available because password last set is out of range");
                return new ComputerStatus
                {
                    Connectable = false,
                    Error = ComputerStatus.OldPwd
                };
            }


            if (!await _scanner.CheckPort(computerName))
            {
                Logging.Trace($"{computerName} is not available because port 445 is unavailable");
                return new ComputerStatus
                {
                    Connectable = false,
                    Error = ComputerStatus.PortNotOpen
                }; 
            }
                

            return new ComputerStatus
            {
                Connectable = true,
                Error = null
            };
        }
    }
}