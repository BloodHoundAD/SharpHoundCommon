using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using SharpHoundCommonLib.Enums;

namespace SharpHoundCommonLib
{
    public static class Helpers
    {
        private static readonly HashSet<string> Groups = new() { "268435456", "268435457", "536870912", "536870913" };
        private static readonly HashSet<string> Computers = new() { "805306369" };
        private static readonly HashSet<string> Users = new() { "805306368" };
        
        private static readonly Regex DCReplaceRegex = new Regex("DC=", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        private static readonly Regex SPNRegex = new Regex(@".*\/.*", RegexOptions.Compiled);
        private static readonly DateTime EpochDiff = new DateTime(1970,1,1);

        public static IEnumerable<ParsedGPLink> SplitGPLinkProperty(string linkProp, bool filterDisabled = true)
        {
            foreach (var link in linkProp.Split(']', '[').Where(x => x.StartsWith("LDAP", StringComparison.OrdinalIgnoreCase)))
            {
                var s = link.Split(';');
                var dn = s[0].Substring(s[0].IndexOf("CN=", StringComparison.OrdinalIgnoreCase));
                var status = s[1];

                if (filterDisabled)
                    // 1 and 3 represent Disabled, Not Enforced and Disabled, Enforced respectively.
                    if (status is "3" or "1")
                        continue;

                yield return new ParsedGPLink
                {
                    Status = status,
                    DistinguishedName = dn
                };
            }
        }
        
        /// <summary>
        /// Attempts to convert a SamAccountType value to the appropriate type enum
        /// </summary>
        /// <param name="samAccountType"></param>
        /// <returns><c>Label</c> value representing type</returns>
        internal static Label SamAccountTypeToType(string samAccountType)
        {
            if (Groups.Contains(samAccountType))
                return Label.Group;

            if (Users.Contains(samAccountType))
                return Label.User;

            if (Computers.Contains(samAccountType))
                return Label.Computer;

            return Label.Unknown;
        }
        
        /// <summary>
        /// Converts a string SID to its hex representation for LDAP searches
        /// </summary>
        /// <param name="sid">String security identifier to convert</param>
        /// <returns>String representation to use in LDAP filters</returns>
        internal static string ConvertSidToHexSid(string sid)
        {
            var securityIdentifier = new SecurityIdentifier(sid);
            var sidBytes = new byte[securityIdentifier.BinaryLength];
            securityIdentifier.GetBinaryForm(sidBytes, 0);

            var output = $"\\{BitConverter.ToString(sidBytes).Replace('-', '\\')}";
            return output;
        }
        
        /// <summary>
        /// Extracts an active directory domain name from a DistinguishedName 
        /// </summary>
        /// <param name="distinguishedName">Distinguished Name to extract domain from</param>
        /// <returns>String representing the domain name of this object</returns>
        internal static string DistinguishedNameToDomain(string distinguishedName)
        {
            var temp = distinguishedName.Substring(distinguishedName.IndexOf("DC=",
                StringComparison.CurrentCultureIgnoreCase));
            temp = DCReplaceRegex.Replace(temp, "").Replace(",", ".").ToUpper();
            return temp;
        }
        
        /// <summary>
        /// Strips a "serviceprincipalname" entry down to just its hostname
        /// </summary>
        /// <param name="target">Raw service principal name</param>
        /// <returns>Stripped service principal name with (hopefully) just the hostname</returns>
        internal static string StripServicePrincipalName(string target)
        {
            return SPNRegex.IsMatch(target) ? target.Split('/')[1].Split(':')[0] : target;
        }
        
        /// <summary>
        /// Converts a string to its base64 representation
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        internal static string Base64(string input)
        {
            var plainBytes = Encoding.UTF8.GetBytes(input);
            return Convert.ToBase64String(plainBytes);
        }

        /// <summary>
        /// Checks if a specified port is open on a host. Defaults to 445 (SMB)
        /// </summary>
        /// <param name="hostname"></param>
        /// <param name="port"></param>
        /// <param name="timeout">Timeout in milliseconds</param>
        /// <returns>True if port is open, otherwise false</returns>
        internal static async Task<bool> CheckPort(string hostname, int port = 445, int timeout = 500)
        {
            try
            {
                using var client = new TcpClient();
                var ca = client.ConnectAsync(hostname, port);
                await Task.WhenAny(ca, Task.Delay(timeout));
                client.Close();
                if (!ca.IsFaulted && ca.IsCompleted) return true;
                Logging.Debug($"{hostname} did not respond to ping");
                return false;
            }
            catch
            {
                return false;
            }
        }
        
        /// <summary>
        /// Converts a windows file time to unix epoch time
        /// </summary>
        /// <param name="ldapTime"></param>
        /// <returns></returns>
        public static long ConvertFileTimeToUnixEpoch(string ldapTime)
        {
            if (ldapTime == null)
                return -1;
            
            var time = long.Parse(ldapTime);
            if (time == 0)
                return 0;

            long toReturn;

            try
            {
                toReturn = (long) Math.Floor(DateTime.FromFileTimeUtc(time).Subtract(EpochDiff).TotalSeconds);
            }
            catch
            {
                toReturn = -1;
            }

            return toReturn;
        }
        
        /// <summary>
        /// Converts a windows file time to unix epoch time
        /// </summary>
        /// <param name="ldapTime"></param>
        /// <returns></returns>
        public static long ConvertTimestampToUnixEpoch(string ldapTime)
        {
            var dt = DateTime.ParseExact(ldapTime, "yyyyMMddHHmmss.0K", CultureInfo.CurrentCulture);
            return (long) dt.Subtract(EpochDiff).TotalSeconds;
        }
    }

    public class ParsedGPLink
    {
        public string DistinguishedName { get; set; }
        public string Status { get; set; }
    }
}