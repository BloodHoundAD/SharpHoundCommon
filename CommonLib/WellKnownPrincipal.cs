using System.Text.RegularExpressions;
using CommonLib.Enums;

namespace CommonLib
{
    public class WellKnownPrincipal
    {
        internal Label Type { get; set; }

        private string _principalName;
        /// <summary>
        /// Setter to ensure that the principal name is always upper case
        /// </summary>
        internal string Name
        {
            get => _principalName;
            set => _principalName = value?.ToUpper();
        }

        public WellKnownPrincipal(string name, Label type)
        {
            Name = name;
            Type = type;
        }
        
        /// <summary>
        /// Gets the principal associate with a well known SID
        /// </summary>
        /// <param name="sid"></param>
        /// <param name="commonPrincipal"></param>
        /// <returns>True if SID matches a well known principal, false otherwise</returns>
        public static bool GetWellKnownPrincipal(string sid, out WellKnownPrincipal commonPrincipal)
        {
            switch (sid)
            {
                case "S-1-0":
                    commonPrincipal = new WellKnownPrincipal("Null Authority", Label.User);
                    break;
                case "S-1-0-0":
                    commonPrincipal = new WellKnownPrincipal("Nobody", Label.User);
                    break;
                case "S-1-1":
                    commonPrincipal = new WellKnownPrincipal("World Authority", Label.User);
                    break;
                case "S-1-1-0":
                    commonPrincipal = new WellKnownPrincipal("Everyone", Label.Group);
                    break;
                case "S-1-2":
                    commonPrincipal = new WellKnownPrincipal("Local Authority", Label.User);
                    break;
                case "S-1-2-0":
                    commonPrincipal = new WellKnownPrincipal("Local", Label.Group);
                    break;
                case "S-1-2-1":
                    commonPrincipal = new WellKnownPrincipal("Console Logon", Label.Group);
                    break;
                case "S-1-3":
                    commonPrincipal = new WellKnownPrincipal("Creator Authority", Label.User);
                    break;
                case "S-1-3-0":
                    commonPrincipal = new WellKnownPrincipal("Creator Owner", Label.User);
                    break;
                case "S-1-3-1":
                    commonPrincipal = new WellKnownPrincipal("Creator Label.Group", Label.Group);
                    break;
                case "S-1-3-2":
                    commonPrincipal = new WellKnownPrincipal("Creator Owner Server", Label.Computer);
                    break;
                case "S-1-3-3":
                    commonPrincipal = new WellKnownPrincipal("Creator Label.Group Server", Label.Computer);
                    break;
                case "S-1-3-4":
                    commonPrincipal = new WellKnownPrincipal("Owner Rights", Label.Group);
                    break;
                case "S-1-4":
                    commonPrincipal = new WellKnownPrincipal("Non-unique Authority", Label.User);
                    break;
                case "S-1-5":
                    commonPrincipal = new WellKnownPrincipal("NT Authority", Label.User);
                    break;
                case "S-1-5-1":
                    commonPrincipal = new WellKnownPrincipal("Dialup", Label.Group);
                    break;
                case "S-1-5-2":
                    commonPrincipal = new WellKnownPrincipal("Network", Label.Group);
                    break;
                case "S-1-5-3":
                    commonPrincipal = new WellKnownPrincipal("Batch", Label.Group);
                    break;
                case "S-1-5-4":
                    commonPrincipal = new WellKnownPrincipal("Interactive", Label.Group);
                    break;
                case "S-1-5-6":
                    commonPrincipal = new WellKnownPrincipal("Service", Label.Group);
                    break;
                case "S-1-5-7":
                    commonPrincipal = new WellKnownPrincipal("Anonymous", Label.Group);
                    break;
                case "S-1-5-8":
                    commonPrincipal = new WellKnownPrincipal("Proxy", Label.Group);
                    break;
                case "S-1-5-9":
                    commonPrincipal = new WellKnownPrincipal("Enterprise Domain Controllers", Label.Group);
                    break;
                case "S-1-5-10":
                    commonPrincipal = new WellKnownPrincipal("Principal Self", Label.User);
                    break;
                case "S-1-5-11":
                    commonPrincipal = new WellKnownPrincipal("Authenticated Label.Users", Label.Group);
                    break;
                case "S-1-5-12":
                    commonPrincipal = new WellKnownPrincipal("Restricted Code", Label.Group);
                    break;
                case "S-1-5-13":
                    commonPrincipal = new WellKnownPrincipal("Terminal Server Label.Users", Label.Group);
                    break;
                case "S-1-5-14":
                    commonPrincipal = new WellKnownPrincipal("Remote Interactive Logon", Label.Group);
                    break;
                case "S-1-5-15":
                    commonPrincipal = new WellKnownPrincipal("This Organization ", Label.Group);
                    break;
                case "S-1-5-17":
                    commonPrincipal = new WellKnownPrincipal("This Organization ", Label.Group);
                    break;
                case "S-1-5-18":
                    commonPrincipal = new WellKnownPrincipal("Local System", Label.User);
                    break;
                case "S-1-5-19":
                    commonPrincipal = new WellKnownPrincipal("NT Authority", Label.User);
                    break;
                case "S-1-5-20":
                    commonPrincipal = new WellKnownPrincipal("NT Authority", Label.User);
                    break;
                case "S-1-5-113":
                    commonPrincipal = new WellKnownPrincipal("Local Account", Label.User);
                    break;
                case "S-1-5-114":
                    commonPrincipal = new WellKnownPrincipal("Local Account and Member of Administrators Label.Group", Label.User);
                    break;
                case "S-1-5-80-0":
                    commonPrincipal = new WellKnownPrincipal("All Services ", Label.Group);
                    break;
                case "S-1-5-32-544":
                    commonPrincipal = new WellKnownPrincipal("Administrators", Label.Group);
                    break;
                case "S-1-5-32-545":
                    commonPrincipal = new WellKnownPrincipal("Label.Users", Label.Group);
                    break;
                case "S-1-5-32-546":
                    commonPrincipal = new WellKnownPrincipal("Guests", Label.Group);
                    break;
                case "S-1-5-32-547":
                    commonPrincipal = new WellKnownPrincipal("Power Label.Users", Label.Group);
                    break;
                case "S-1-5-32-548":
                    commonPrincipal = new WellKnownPrincipal("Account Operators", Label.Group);
                    break;
                case "S-1-5-32-549":
                    commonPrincipal = new WellKnownPrincipal("Server Operators", Label.Group);
                    break;
                case "S-1-5-32-550":
                    commonPrincipal = new WellKnownPrincipal("Print Operators", Label.Group);
                    break;
                case "S-1-5-32-551":
                    commonPrincipal = new WellKnownPrincipal("Backup Operators", Label.Group);
                    break;
                case "S-1-5-32-552":
                    commonPrincipal = new WellKnownPrincipal("Replicators", Label.Group);
                    break;
                case "S-1-5-32-554":
                    commonPrincipal = new WellKnownPrincipal("Pre-Windows 2000 Compatible Access", Label.Group);
                    break;
                case "S-1-5-32-555":
                    commonPrincipal = new WellKnownPrincipal("Remote Desktop Label.Users", Label.Group);
                    break;
                case "S-1-5-32-556":
                    commonPrincipal = new WellKnownPrincipal("Network Configuration Operators", Label.Group);
                    break;
                case "S-1-5-32-557":
                    commonPrincipal = new WellKnownPrincipal("Incoming Forest Trust Builders", Label.Group);
                    break;
                case "S-1-5-32-558":
                    commonPrincipal = new WellKnownPrincipal("Performance Monitor Label.Users", Label.Group);
                    break;
                case "S-1-5-32-559":
                    commonPrincipal = new WellKnownPrincipal("Performance Log Label.Users", Label.Group);
                    break;
                case "S-1-5-32-560":
                    commonPrincipal = new WellKnownPrincipal("Windows Authorization Access Label.Group", Label.Group);
                    break;
                case "S-1-5-32-561":
                    commonPrincipal = new WellKnownPrincipal("Terminal Server License Servers", Label.Group);
                    break;
                case "S-1-5-32-562":
                    commonPrincipal = new WellKnownPrincipal("Distributed COM Label.Users", Label.Group);
                    break;
                case "S-1-5-32-568":
                    commonPrincipal = new WellKnownPrincipal("IIS_IUSRS", Label.Group);
                    break;
                case "S-1-5-32-569":
                    commonPrincipal = new WellKnownPrincipal("Cryptographic Operators", Label.Group);
                    break;
                case "S-1-5-32-573":
                    commonPrincipal = new WellKnownPrincipal("Event Log Readers", Label.Group);
                    break;
                case "S-1-5-32-574":
                    commonPrincipal = new WellKnownPrincipal("Certificate Service DCOM Access", Label.Group);
                    break;
                case "S-1-5-32-575":
                    commonPrincipal = new WellKnownPrincipal("RDS Remote Access Servers", Label.Group);
                    break;
                case "S-1-5-32-576":
                    commonPrincipal = new WellKnownPrincipal("RDS Endpoint Servers", Label.Group);
                    break;
                case "S-1-5-32-577":
                    commonPrincipal = new WellKnownPrincipal("RDS Management Servers", Label.Group);
                    break;
                case "S-1-5-32-578":
                    commonPrincipal = new WellKnownPrincipal("Hyper-V Administrators", Label.Group);
                    break;
                case "S-1-5-32-579":
                    commonPrincipal = new WellKnownPrincipal("Access Control Assistance Operators", Label.Group);
                    break;
                case "S-1-5-32-580":
                    commonPrincipal = new WellKnownPrincipal("Remote Management Label.Users", Label.Group);
                    break;
                default:
                    commonPrincipal = null;
                    break;

            }

            return commonPrincipal != null;
        }
        
        /// <summary>
        /// Converts the provided SID to the BloodHound well known sid format if it matches a well known SID
        /// </summary>
        /// <param name="sid">Security Identifier</param>
        /// <param name="domain">Domain to append if common SID is matched</param>
        /// <returns>Sid with the domain appended if common SID is provided, else with no change</returns>
        internal static string TryConvert(string sid, string domain)
        {
            if (GetWellKnownPrincipal(sid, out _))
            {
                if (sid == "S-1-5-9")
                {
                    var forest = GetForestName(domain);
                    return $"{forest}-{sid}".ToUpper();
                }
                
                return $"{domain}-{sid}".ToUpper();
            }

            return sid;
        }
    }
}