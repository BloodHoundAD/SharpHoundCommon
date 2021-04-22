using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using CommonLib.Enums;

namespace CommonLib
{
    public static class Helpers
    {
        private static readonly HashSet<string> Groups = new() { "268435456", "268435457", "536870912", "536870913" };
        private static readonly HashSet<string> Computers = new() { "805306369" };
        private static readonly HashSet<string> Users = new() { "805306368" };
        
        private static readonly Regex DCReplaceRegex = new Regex("DC=", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        private static readonly Regex SPNRegex = new Regex(@".*\/.*", RegexOptions.Compiled);
        
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
    }
}