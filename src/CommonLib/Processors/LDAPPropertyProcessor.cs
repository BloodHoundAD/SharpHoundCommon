using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Threading.Tasks;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib.Processors
{
    public class LDAPPropertyProcessor
    {
        private static readonly string[] ReservedAttributes =
        {
            "pwdlastset", "lastlogon", "lastlogontimestamp", "objectsid",
            "sidhistory", "useraccountcontrol", "operatingsystem",
            "operatingsystemservicepack", "serviceprincipalname", "displayname", "mail", "title",
            "homedirectory", "description", "admincount", "userpassword", "gpcfilesyspath", "objectclass",
            "msds-behavior-version", "objectguid", "name", "gpoptions", "msds-allowedtodelegateto",
            "msDS-allowedtoactonbehalfofotheridentity", "displayname",
            "sidhistory", "samaccountname", "samaccounttype", "objectsid", "objectguid", "objectclass",
            "samaccountname", "msds-groupmsamembership",
            "distinguishedname", "memberof", "logonhours", "ntsecuritydescriptor", "dsasignature", "repluptodatevector",
            "member", "whenCreated"
        };

        private readonly ILDAPUtils _utils;

        public LDAPPropertyProcessor(ILDAPUtils utils)
        {
            _utils = utils;
        }

        private static Dictionary<string, object> GetCommonProps(ISearchResultEntry entry)
        {
            return new Dictionary<string, object>
            {
                {
                    "description", entry.GetProperty("description")
                },
                {
                    "whencreated", Helpers.ConvertTimestampToUnixEpoch(entry.GetProperty("whenCreated"))
                }
            };
        }

        /// <summary>
        ///     Reads specific LDAP properties related to Domains
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public static Dictionary<string, object> ReadDomainProperties(ISearchResultEntry entry)
        {
            var props = GetCommonProps(entry);

            if (!int.TryParse(entry.GetProperty("msds-behavior-version"), out var level)) level = -1;

            props.Add("functionallevel", FunctionalLevelToString(level));

            return props;
        }

        /// <summary>
        ///     Converts a numeric representation of a functional level to its appropriate functional level string
        /// </summary>
        /// <param name="level"></param>
        /// <returns></returns>
        public static string FunctionalLevelToString(int level)
        {
            var functionalLevel = level switch
            {
                0 => "2000 Mixed/Native",
                1 => "2003 Interim",
                2 => "2003",
                3 => "2008",
                4 => "2008 R2",
                5 => "2012",
                6 => "2012 R2",
                7 => "2016",
                _ => "Unknown"
            };

            return functionalLevel;
        }

        /// <summary>
        ///     Reads specific LDAP properties related to GPOs
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public static Dictionary<string, object> ReadGPOProperties(ISearchResultEntry entry)
        {
            var props = GetCommonProps(entry);
            props.Add("gpcpath", entry.GetProperty("gpcfilesyspath")?.ToUpper());
            return props;
        }

        /// <summary>
        ///     Reads specific LDAP properties related to OUs
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public static Dictionary<string, object> ReadOUProperties(ISearchResultEntry entry)
        {
            var props = GetCommonProps(entry);
            return props;
        }

        /// <summary>
        ///     Reads specific LDAP properties related to Groups
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public static Dictionary<string, object> ReadGroupProperties(ISearchResultEntry entry)
        {
            var props = GetCommonProps(entry);

            var ac = entry.GetProperty("admincount");
            if (ac != null)
            {
                var a = int.Parse(ac);
                props.Add("admincount", a != 0);
            }
            else
            {
                props.Add("admincount", false);
            }

            return props;
        }

        public static Dictionary<string, object> ReadCAProperties(ISearchResultEntry entry)
        {
            var props = GetCommonProps(entry);
            if (entry.GetIntProperty("flags", out var flags))
            {
                Logging.Info($"Parsed flags to {flags}");
                props.Add("flags", (PKICertificateAuthorityFlags) flags);    
            }
            
            return props;
        }
        
        public static Dictionary<string, object> ReadCertTemplateProperties(ISearchResultEntry entry)
        {
            var props = GetCommonProps(entry);
            props.Add("validityperiod", ConvertPKIPeriod(entry.GetByteProperty("pkiexpirationperiod")));
            props.Add("renewalperiod", ConvertPKIPeriod(entry.GetByteProperty("pkioverlapperiod")));
            if (entry.GetIntProperty("mspki-template-schema-version", out var schemaVersion))
            {
                props.Add("schemaversion", schemaVersion);
            }
            props.Add("displayname", entry.GetProperty("displayname"));
            props.Add("oid", new Oid(entry.GetProperty("mspki-cert-template-oid")));
            if (entry.GetIntProperty("mspki-enrollment-flag", out var enrollmentFlagsRaw))
            {
                var enrollmentFlags = (PKIEnrollmentFlag)enrollmentFlagsRaw;
                props.Add("requiresmanagerapproval", enrollmentFlags.HasFlag(PKIEnrollmentFlag.PEND_ALL_REQUESTS));
            }

            if (entry.GetIntProperty("mspki-certificate-name-flag", out var nameFlagsRaw))
            {
                var nameFlags = (PKICertificateNameFlag)nameFlagsRaw;
                props.Add("enrolleesuppliessubject", nameFlags.HasFlag(PKICertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT));
            }
            
            props.Add("ekus", entry.GetArrayProperty("pkiextendedkeyusage"));
            if (entry.GetIntProperty("mspki-ra-signature", out var authorizedSignatures))
            {
                props.Add("authorizedsignatures", authorizedSignatures);
            }
            
            return props;
        }

        /// <summary>
        ///     Reads specific LDAP properties related to Users
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public async Task<UserProperties> ReadUserProperties(ISearchResultEntry entry)
        {
            var userProps = new UserProperties();
            var props = GetCommonProps(entry);

            var uac = entry.GetProperty("useraccountcontrol");
            bool enabled, trustedToAuth, sensitive, dontReqPreAuth, passwdNotReq, unconstrained, pwdNeverExpires;
            if (int.TryParse(uac, out var flag))
            {
                var flags = (UacFlags) flag;
                enabled = (flags & UacFlags.AccountDisable) == 0;
                trustedToAuth = (flags & UacFlags.TrustedToAuthForDelegation) != 0;
                sensitive = (flags & UacFlags.NotDelegated) != 0;
                dontReqPreAuth = (flags & UacFlags.DontReqPreauth) != 0;
                passwdNotReq = (flags & UacFlags.PasswordNotRequired) != 0;
                unconstrained = (flags & UacFlags.TrustedForDelegation) != 0;
                pwdNeverExpires = (flags & UacFlags.DontExpirePassword) != 0;
            }
            else
            {
                trustedToAuth = false;
                enabled = true;
                sensitive = false;
                dontReqPreAuth = false;
                passwdNotReq = false;
                unconstrained = false;
                pwdNeverExpires = false;
            }

            props.Add("sensitive", sensitive);
            props.Add("dontreqpreauth", dontReqPreAuth);
            props.Add("passwordnotreqd", passwdNotReq);
            props.Add("unconstraineddelegation", unconstrained);
            props.Add("pwdneverexpires", pwdNeverExpires);
            props.Add("enabled", enabled);
            props.Add("trustedtoauth", trustedToAuth);
            var domain = Helpers.DistinguishedNameToDomain(entry.DistinguishedName);

            var comps = new List<TypedPrincipal>();
            if (trustedToAuth)
            {
                var delegates = entry.GetArrayProperty("msds-allowedToDelegateTo");
                props.Add("allowedtodelegate", delegates);

                foreach (var d in delegates)
                {
                    if (d == null)
                        continue;

                    var resolvedHost = await _utils.ResolveHostToSid(d, domain);
                    if (resolvedHost != null && (resolvedHost.Contains(".") || resolvedHost.Contains("S-1")))
                        comps.Add(new TypedPrincipal
                        {
                            ObjectIdentifier = resolvedHost,
                            ObjectType = Label.Computer
                        });
                }
            }

            userProps.AllowedToDelegate = comps.Distinct().ToArray();

            props.Add("lastlogon", Helpers.ConvertFileTimeToUnixEpoch(entry.GetProperty("lastlogon")));
            props.Add("lastlogontimestamp",
                Helpers.ConvertFileTimeToUnixEpoch(entry.GetProperty("lastlogontimestamp")));
            props.Add("pwdlastset", Helpers.ConvertFileTimeToUnixEpoch(entry.GetProperty("pwdlastset")));
            var spn = entry.GetArrayProperty("serviceprincipalname");
            props.Add("serviceprincipalnames", spn);
            props.Add("hasspn", spn.Length > 0);
            props.Add("displayname", entry.GetProperty("displayname"));
            props.Add("email", entry.GetProperty("mail"));
            props.Add("title", entry.GetProperty("title"));
            props.Add("homedirectory", entry.GetProperty("homedirectory"));
            props.Add("userpassword", entry.GetProperty("userpassword"));

            var ac = entry.GetProperty("admincount");
            if (ac != null)
            {
                if (int.TryParse(ac, out var parsed))
                    props.Add("admincount", parsed != 0);
                else
                    props.Add("admincount", false);
            }
            else
            {
                props.Add("admincount", false);
            }

            var sh = entry.GetByteArrayProperty("sidhistory");
            var sidHistoryList = new List<string>();
            var sidHistoryPrincipals = new List<TypedPrincipal>();
            foreach (var sid in sh)
            {
                string sSid;
                try
                {
                    sSid = new SecurityIdentifier(sid, 0).Value;
                }
                catch
                {
                    continue;
                }

                sidHistoryList.Add(sSid);

                var res = _utils.ResolveIDAndType(sSid, domain);

                sidHistoryPrincipals.Add(res);
            }

            userProps.SidHistory = sidHistoryPrincipals.Distinct().ToArray();

            props.Add("sidhistory", sidHistoryList.ToArray());

            userProps.Props = props;

            return userProps;
        }

        /// <summary>
        ///     Reads specific LDAP properties related to Computers
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public async Task<ComputerProperties> ReadComputerProperties(ISearchResultEntry entry)
        {
            var compProps = new ComputerProperties();
            var props = GetCommonProps(entry);

            var uac = entry.GetProperty("useraccountcontrol");
            bool enabled, unconstrained, trustedToAuth;
            if (int.TryParse(uac, out var flag))
            {
                var flags = (UacFlags) flag;
                enabled = (flags & UacFlags.AccountDisable) == 0;
                unconstrained = (flags & UacFlags.TrustedForDelegation) == UacFlags.TrustedForDelegation;
                trustedToAuth = (flags & UacFlags.TrustedToAuthForDelegation) != 0;
            }
            else
            {
                unconstrained = false;
                enabled = true;
                trustedToAuth = false;
            }

            var domain = Helpers.DistinguishedNameToDomain(entry.DistinguishedName);

            var comps = new List<TypedPrincipal>();
            if (trustedToAuth)
            {
                var delegates = entry.GetArrayProperty("msds-allowedToDelegateTo");
                props.Add("allowedtodelegate", delegates);

                foreach (var d in delegates)
                {
                    var hname = d.Contains("/") ? d.Split('/')[1] : d;
                    hname = hname.Split(':')[0];
                    var resolvedHost = await _utils.ResolveHostToSid(hname, domain);
                    if (resolvedHost != null && (resolvedHost.Contains(".") || resolvedHost.Contains("S-1")))
                        comps.Add(new TypedPrincipal
                        {
                            ObjectIdentifier = resolvedHost,
                            ObjectType = Label.Computer
                        });
                }
            }

            compProps.AllowedToDelegate = comps.Distinct().ToArray();

            var allowedToActPrincipals = new List<TypedPrincipal>();
            var rawAllowedToAct = entry.GetByteProperty("msDS-AllowedToActOnBehalfOfOtherIdentity");
            if (rawAllowedToAct != null)
            {
                var sd = _utils.MakeSecurityDescriptor();
                sd.SetSecurityDescriptorBinaryForm(rawAllowedToAct, AccessControlSections.Access);
                foreach (var rule in sd.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                {
                    var res = _utils.ResolveIDAndType(rule.IdentityReference(), domain);
                    allowedToActPrincipals.Add(res);
                }
            }

            compProps.AllowedToAct = allowedToActPrincipals.ToArray();

            props.Add("enabled", enabled);
            props.Add("unconstraineddelegation", unconstrained);
            props.Add("trustedtoauth", trustedToAuth);
            props.Add("lastlogon", Helpers.ConvertFileTimeToUnixEpoch(entry.GetProperty("lastlogon")));
            props.Add("lastlogontimestamp",
                Helpers.ConvertFileTimeToUnixEpoch(entry.GetProperty("lastlogontimestamp")));
            props.Add("pwdlastset", Helpers.ConvertFileTimeToUnixEpoch(entry.GetProperty("pwdlastset")));
            props.Add("serviceprincipalnames", entry.GetArrayProperty("serviceprincipalname"));
            var os = entry.GetProperty("operatingsystem");
            var sp = entry.GetProperty("operatingsystemservicepack");

            if (sp != null) os = $"{os} {sp}";

            props.Add("operatingsystem", os);

            var sh = entry.GetByteArrayProperty("sidhistory");
            var sidHistoryList = new List<string>();
            var sidHistoryPrincipals = new List<TypedPrincipal>();
            foreach (var sid in sh)
            {
                string sSid;
                try
                {
                    sSid = new SecurityIdentifier(sid, 0).Value;
                }
                catch
                {
                    continue;
                }

                sidHistoryList.Add(sSid);

                var res = _utils.ResolveIDAndType(sSid, domain);

                sidHistoryPrincipals.Add(res);
            }

            compProps.SidHistory = sidHistoryPrincipals.ToArray();

            props.Add("sidhistory", sidHistoryList.ToArray());

            compProps.Props = props;

            return compProps;
        }

        /// <summary>
        ///     Attempts to parse all LDAP attributes outside of the ones already collected and converts them to a human readable
        ///     format using a best guess
        /// </summary>
        /// <param name="entry"></param>
        private static Dictionary<string, object> ParseAllProperties(ISearchResultEntry entry)
        {
            var flag = IsTextUnicodeFlags.IS_TEXT_UNICODE_STATISTICS;
            var props = new Dictionary<string, object>();

            foreach (var property in entry.PropertyNames())
            {
                if (ReservedAttributes.Contains(property))
                    continue;

                var collCount = entry.PropCount(property);
                if (collCount == 0)
                    continue;

                if (collCount == 1)
                {
                    var testBytes = entry.GetByteProperty(property);

                    if (testBytes == null || testBytes.Length == 0 ||
                        !IsTextUnicode(testBytes, testBytes.Length, ref flag)) continue;

                    var testString = entry.GetProperty(property);

                    if (!string.IsNullOrEmpty(testString))
                        if (property == "badpasswordtime")
                            props.Add(property, Helpers.ConvertFileTimeToUnixEpoch(testString));
                        else
                            props.Add(property, BestGuessConvert(testString));
                }
                else
                {
                    var arrBytes = entry.GetByteArrayProperty(property);
                    if (arrBytes.Length == 0 || !IsTextUnicode(arrBytes[0], arrBytes[0].Length, ref flag))
                        continue;

                    var arr = entry.GetArrayProperty(property);
                    if (arr.Length > 0) props.Add(property, arr.Select(BestGuessConvert).ToArray());
                }
            }

            return props;
        }

        /// <summary>
        ///     Does a best guess conversion of the property to a type useable by the UI
        /// </summary>
        /// <param name="property"></param>
        /// <returns></returns>
        private static object BestGuessConvert(string property)
        {
            //Parse boolean values
            if (bool.TryParse(property, out var boolResult)) return boolResult;

            //A string ending with 0Z is likely a timestamp
            if (property.EndsWith("0Z")) return Helpers.ConvertTimestampToUnixEpoch(property);

            //This string corresponds to the max int, and is usually set in accountexpires
            if (property == "9223372036854775807") return -1;

            return property;
        }
        
        private static string ConvertPKIPeriod(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0)
                return "Unknown";
            
            // ref: https://www.sysadmins.lv/blog-en/how-to-convert-pkiexirationperiod-and-pkioverlapperiod-active-directory-attributes.aspx
            try
            {
                Array.Reverse(bytes);
                var temp = BitConverter.ToString(bytes).Replace("-", "");
                var value = Convert.ToInt64(temp, 16) * -.0000001;

                if (value % 31536000 == 0 && value / 31536000 >= 1)
                {
                    if (value / 31536000 == 1)
                    {
                        return "1 year";
                    }

                    return $"{value / 31536000} years";
                }

                if (value % 2592000 == 0 && value / 2592000 >= 1)
                {
                    if (value / 2592000 == 1)
                    {
                        return "1 month";
                    }

                    return $"{value / 2592000} months";
                }
                if (value % 604800 == 0 && value / 604800 >= 1)
                {
                    if (value / 604800 == 1)
                    {
                        return "1 week";
                    }

                    return $"{value / 604800} weeks";
                }
                if (value % 86400 == 0 && value / 86400 >= 1)
                {
                    if (value / 86400 == 1)
                    {
                        return "1 day";
                    }

                    return $"{value / 86400} days";
                }
                if (value % 3600 == 0 && value / 3600 >= 1)
                {
                    if (value / 3600 == 1)
                    {
                        return "1 hour";
                    }

                    return $"{value / 3600} hours";
                }
                return "";
            }
            catch (Exception)
            {
                return "Unknown";
            }
        }  

        [DllImport("Advapi32", SetLastError = false)]
        private static extern bool IsTextUnicode(byte[] buf, int len, ref IsTextUnicodeFlags opt);

        [Flags]
        [SuppressMessage("ReSharper", "UnusedMember.Local")]
        [SuppressMessage("ReSharper", "InconsistentNaming")]
        private enum IsTextUnicodeFlags
        {
            IS_TEXT_UNICODE_ASCII16 = 0x0001,
            IS_TEXT_UNICODE_REVERSE_ASCII16 = 0x0010,

            IS_TEXT_UNICODE_STATISTICS = 0x0002,
            IS_TEXT_UNICODE_REVERSE_STATISTICS = 0x0020,

            IS_TEXT_UNICODE_CONTROLS = 0x0004,
            IS_TEXT_UNICODE_REVERSE_CONTROLS = 0x0040,

            IS_TEXT_UNICODE_SIGNATURE = 0x0008,
            IS_TEXT_UNICODE_REVERSE_SIGNATURE = 0x0080,

            IS_TEXT_UNICODE_ILLEGAL_CHARS = 0x0100,
            IS_TEXT_UNICODE_ODD_LENGTH = 0x0200,
            IS_TEXT_UNICODE_DBCS_LEADBYTE = 0x0400,
            IS_TEXT_UNICODE_NULL_BYTES = 0x1000,

            IS_TEXT_UNICODE_UNICODE_MASK = 0x000F,
            IS_TEXT_UNICODE_REVERSE_MASK = 0x00F0,
            IS_TEXT_UNICODE_NOT_UNICODE_MASK = 0x0F00,
            IS_TEXT_UNICODE_NOT_ASCII_MASK = 0xF000
        }
    }


    public class UserProperties
    {
        public Dictionary<string, object> Props { get; set; }
        public TypedPrincipal[] AllowedToDelegate { get; set; }
        public TypedPrincipal[] SidHistory { get; set; }
    }

    public class ComputerProperties
    {
        public Dictionary<string, object> Props { get; set; }
        public TypedPrincipal[] AllowedToDelegate { get; set; }
        public TypedPrincipal[] AllowedToAct { get; set; }
        public TypedPrincipal[] SidHistory { get; set; }
    }

    public class CertTemplateProperties
    {
        public Dictionary<string, object> Props { get; set; }
        public bool RequiresManagerApproval { get; set; }
        public bool EnrolleeSuppliesSubject { get; set; }
        
    }
}