using CommonLib.Enums;
using CommonLib.OutputTypes;

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

        public static bool GetWellKnownPrincipal(string sid, string domain, out TypedPrincipal commonPrincipal)
        {
            if (!GetWellKnownPrincipal(sid, out commonPrincipal)) return false;
            commonPrincipal.ObjectIdentifier = TryConvert(commonPrincipal.ObjectIdentifier, domain);
            return true;

        }
        
        /// <summary>
        /// Gets the principal associated with a well known SID
        /// </summary>
        /// <param name="sid"></param>
        /// <param name="commonPrincipal"></param>
        /// <returns>True if SID matches a well known principal, false otherwise</returns>
        public static bool GetWellKnownPrincipal(string sid, out TypedPrincipal commonPrincipal)
        {
            switch (sid)
            {
                case "S-1-0":
                    commonPrincipal = new TypedPrincipal("Null Authority", Label.User);
                    break;
                case "S-1-0-0":
                    commonPrincipal = new TypedPrincipal("Nobody", Label.User);
                    break;
                case "S-1-1":
                    commonPrincipal = new TypedPrincipal("World Authority", Label.User);
                    break;
                case "S-1-1-0":
                    commonPrincipal = new TypedPrincipal("Everyone", Label.Group);
                    break;
                case "S-1-2":
                    commonPrincipal = new TypedPrincipal("Local Authority", Label.User);
                    break;
                case "S-1-2-0":
                    commonPrincipal = new TypedPrincipal("Local", Label.Group);
                    break;
                case "S-1-2-1":
                    commonPrincipal = new TypedPrincipal("Console Logon", Label.Group);
                    break;
                case "S-1-3":
                    commonPrincipal = new TypedPrincipal("Creator Authority", Label.User);
                    break;
                case "S-1-3-0":
                    commonPrincipal = new TypedPrincipal("Creator Owner", Label.User);
                    break;
                case "S-1-3-1":
                    commonPrincipal = new TypedPrincipal("Creator Label.Group", Label.Group);
                    break;
                case "S-1-3-2":
                    commonPrincipal = new TypedPrincipal("Creator Owner Server", Label.Computer);
                    break;
                case "S-1-3-3":
                    commonPrincipal = new TypedPrincipal("Creator Label.Group Server", Label.Computer);
                    break;
                case "S-1-3-4":
                    commonPrincipal = new TypedPrincipal("Owner Rights", Label.Group);
                    break;
                case "S-1-4":
                    commonPrincipal = new TypedPrincipal("Non-unique Authority", Label.User);
                    break;
                case "S-1-5":
                    commonPrincipal = new TypedPrincipal("NT Authority", Label.User);
                    break;
                case "S-1-5-1":
                    commonPrincipal = new TypedPrincipal("Dialup", Label.Group);
                    break;
                case "S-1-5-2":
                    commonPrincipal = new TypedPrincipal("Network", Label.Group);
                    break;
                case "S-1-5-3":
                    commonPrincipal = new TypedPrincipal("Batch", Label.Group);
                    break;
                case "S-1-5-4":
                    commonPrincipal = new TypedPrincipal("Interactive", Label.Group);
                    break;
                case "S-1-5-6":
                    commonPrincipal = new TypedPrincipal("Service", Label.Group);
                    break;
                case "S-1-5-7":
                    commonPrincipal = new TypedPrincipal("Anonymous", Label.Group);
                    break;
                case "S-1-5-8":
                    commonPrincipal = new TypedPrincipal("Proxy", Label.Group);
                    break;
                case "S-1-5-9":
                    commonPrincipal = new TypedPrincipal("Enterprise Domain Controllers", Label.Group);
                    break;
                case "S-1-5-10":
                    commonPrincipal = new TypedPrincipal("Principal Self", Label.User);
                    break;
                case "S-1-5-11":
                    commonPrincipal = new TypedPrincipal("Authenticated Label.Users", Label.Group);
                    break;
                case "S-1-5-12":
                    commonPrincipal = new TypedPrincipal("Restricted Code", Label.Group);
                    break;
                case "S-1-5-13":
                    commonPrincipal = new TypedPrincipal("Terminal Server Label.Users", Label.Group);
                    break;
                case "S-1-5-14":
                    commonPrincipal = new TypedPrincipal("Remote Interactive Logon", Label.Group);
                    break;
                case "S-1-5-15":
                    commonPrincipal = new TypedPrincipal("This Organization ", Label.Group);
                    break;
                case "S-1-5-17":
                    commonPrincipal = new TypedPrincipal("This Organization ", Label.Group);
                    break;
                case "S-1-5-18":
                    commonPrincipal = new TypedPrincipal("Local System", Label.User);
                    break;
                case "S-1-5-19":
                    commonPrincipal = new TypedPrincipal("NT Authority", Label.User);
                    break;
                case "S-1-5-20":
                    commonPrincipal = new TypedPrincipal("NT Authority", Label.User);
                    break;
                case "S-1-5-113":
                    commonPrincipal = new TypedPrincipal("Local Account", Label.User);
                    break;
                case "S-1-5-114":
                    commonPrincipal = new TypedPrincipal("Local Account and Member of Administrators Label.Group", Label.User);
                    break;
                case "S-1-5-80-0":
                    commonPrincipal = new TypedPrincipal("All Services ", Label.Group);
                    break;
                case "S-1-5-32-544":
                    commonPrincipal = new TypedPrincipal("Administrators", Label.Group);
                    break;
                case "S-1-5-32-545":
                    commonPrincipal = new TypedPrincipal("Label.Users", Label.Group);
                    break;
                case "S-1-5-32-546":
                    commonPrincipal = new TypedPrincipal("Guests", Label.Group);
                    break;
                case "S-1-5-32-547":
                    commonPrincipal = new TypedPrincipal("Power Label.Users", Label.Group);
                    break;
                case "S-1-5-32-548":
                    commonPrincipal = new TypedPrincipal("Account Operators", Label.Group);
                    break;
                case "S-1-5-32-549":
                    commonPrincipal = new TypedPrincipal("Server Operators", Label.Group);
                    break;
                case "S-1-5-32-550":
                    commonPrincipal = new TypedPrincipal("Print Operators", Label.Group);
                    break;
                case "S-1-5-32-551":
                    commonPrincipal = new TypedPrincipal("Backup Operators", Label.Group);
                    break;
                case "S-1-5-32-552":
                    commonPrincipal = new TypedPrincipal("Replicators", Label.Group);
                    break;
                case "S-1-5-32-554":
                    commonPrincipal = new TypedPrincipal("Pre-Windows 2000 Compatible Access", Label.Group);
                    break;
                case "S-1-5-32-555":
                    commonPrincipal = new TypedPrincipal("Remote Desktop Label.Users", Label.Group);
                    break;
                case "S-1-5-32-556":
                    commonPrincipal = new TypedPrincipal("Network Configuration Operators", Label.Group);
                    break;
                case "S-1-5-32-557":
                    commonPrincipal = new TypedPrincipal("Incoming Forest Trust Builders", Label.Group);
                    break;
                case "S-1-5-32-558":
                    commonPrincipal = new TypedPrincipal("Performance Monitor Label.Users", Label.Group);
                    break;
                case "S-1-5-32-559":
                    commonPrincipal = new TypedPrincipal("Performance Log Label.Users", Label.Group);
                    break;
                case "S-1-5-32-560":
                    commonPrincipal = new TypedPrincipal("Windows Authorization Access Label.Group", Label.Group);
                    break;
                case "S-1-5-32-561":
                    commonPrincipal = new TypedPrincipal("Terminal Server License Servers", Label.Group);
                    break;
                case "S-1-5-32-562":
                    commonPrincipal = new TypedPrincipal("Distributed COM Label.Users", Label.Group);
                    break;
                case "S-1-5-32-568":
                    commonPrincipal = new TypedPrincipal("IIS_IUSRS", Label.Group);
                    break;
                case "S-1-5-32-569":
                    commonPrincipal = new TypedPrincipal("Cryptographic Operators", Label.Group);
                    break;
                case "S-1-5-32-573":
                    commonPrincipal = new TypedPrincipal("Event Log Readers", Label.Group);
                    break;
                case "S-1-5-32-574":
                    commonPrincipal = new TypedPrincipal("Certificate Service DCOM Access", Label.Group);
                    break;
                case "S-1-5-32-575":
                    commonPrincipal = new TypedPrincipal("RDS Remote Access Servers", Label.Group);
                    break;
                case "S-1-5-32-576":
                    commonPrincipal = new TypedPrincipal("RDS Endpoint Servers", Label.Group);
                    break;
                case "S-1-5-32-577":
                    commonPrincipal = new TypedPrincipal("RDS Management Servers", Label.Group);
                    break;
                case "S-1-5-32-578":
                    commonPrincipal = new TypedPrincipal("Hyper-V Administrators", Label.Group);
                    break;
                case "S-1-5-32-579":
                    commonPrincipal = new TypedPrincipal("Access Control Assistance Operators", Label.Group);
                    break;
                case "S-1-5-32-580":
                    commonPrincipal = new TypedPrincipal("Remote Management Label.Users", Label.Group);
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
                    var forest = LDAPUtils.GetForest(domain)?.Name;
                    if (forest == null)
                    {
                        Logging.Log("Error getting forest, ENTDC sid is likely incorrect");
                    }
                    return $"{forest}-{sid}".ToUpper();
                }
                
                return $"{domain}-{sid}".ToUpper();
            }

            return sid;
        }
    }
}