using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading.Tasks;
using CommonLib.Enums;
using CommonLib.Output;

namespace CommonLib.Processors
{
    public static class LDAPPropertyProcessor
    {
        private static readonly string[] Props = { "distinguishedname", "samaccounttype", "samaccountname", "dnshostname" };

        public static Dictionary<string, object> ReadDomainProperties(SearchResultEntry entry)
        {
            var props = new Dictionary<string, object> {{"description", entry.GetProperty("description")}};

            if (!int.TryParse(entry.GetProperty("msds-behavior-version"), out var level))
            {
                level = -1;
            }

            var func = level switch
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

            props.Add("functionallevel", func);

            return props;
        }

        public static Dictionary<string, object> ReadGPOProperties(SearchResultEntry entry)
        {
            var props = new Dictionary<string, object>
            {
                {"description", entry.GetProperty("description")},
                {"gpcpath", entry.GetProperty("gpcfilesyspath")}
            };
            return props;
        }

        public static Dictionary<string, object> ReadOUProperties(SearchResultEntry entry)
        {
            var props = new Dictionary<string, object>
            {
                {"description", entry.GetProperty("description")}
            };
            return props;
        }
        
        public static Dictionary<string, object> ReadGroupProperties(SearchResultEntry entry)
        {
            var props = new Dictionary<string, object>
            {
                {"description", entry.GetProperty("description")}
            };
            
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

        public static async Task<UserProperties> ReadUserProperties(SearchResultEntry entry)
        {
            var userProps = new UserProperties();
            var props = new Dictionary<string, object>
            {
                {"description", entry.GetProperty("description")}
            };

            var uac = entry.GetProperty("useraccountcontrol");
            bool enabled, trustedToAuth, sensitive, dontReqPreAuth, passwdNotReq, unconstrained, pwdNeverExpires;
            if (int.TryParse(uac, out var flag))
            {
                var flags = (UAC.UacFlags)flag;
                enabled = (flags & UAC.UacFlags.AccountDisable) == 0;
                trustedToAuth = (flags & UAC.UacFlags.TrustedToAuthForDelegation) != 0;
                sensitive = (flags & UAC.UacFlags.NotDelegated) != 0;
                dontReqPreAuth = (flags & UAC.UacFlags.DontReqPreauth) != 0;
                passwdNotReq = (flags & UAC.UacFlags.PasswordNotRequired) != 0;
                unconstrained = (flags & UAC.UacFlags.TrustedForDelegation) != 0;
                pwdNeverExpires = (flags & UAC.UacFlags.DontExpirePassword) != 0;
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
            var domain = Helpers.DistinguishedNameToDomain(entry.DistinguishedName);
            
            var comps = new List<TypedPrincipal>();
            if (trustedToAuth)
            {
                var delegates = entry.GetPropertyAsArray("msds-allowedToDelegateTo");
                props.Add("allowedtodelegate", delegates);

                foreach (var d in delegates)
                {
                    var hname = d.Contains("/") ? d.Split('/')[1] : d;
                    hname = hname.Split(':')[0];
                    var resolvedHost = await LDAPUtils.Instance.ResolveHostToSid(hname, domain);
                    if (resolvedHost.Contains(".") || resolvedHost.Contains("S-1"))
                    {
                        comps.Add(new TypedPrincipal
                        {
                            ObjectIdentifier = resolvedHost,
                            ObjectType = Label.Computer
                        });
                    }
                }
            }

            userProps.AllowedToDelegate = comps.ToArray();

            props.Add("lastlogon", Helpers.ConvertToUnixEpoch(entry.GetProperty("lastlogon")));
            props.Add("lastlogontimestamp", Helpers.ConvertToUnixEpoch(entry.GetProperty("lastlogontimestamp")));
            props.Add("pwdlastset", Helpers.ConvertToUnixEpoch(entry.GetProperty("pwdlastset")));
            var spn = entry.GetPropertyAsArray("serviceprincipalname");
            props.Add("serviceprincipalnames", spn);
            props.Add("hasspn", spn.Length > 0);
            props.Add("displayname", entry.GetProperty("displayname"));
            props.Add("email", entry.GetProperty("mail"));
            props.Add("title", entry.GetProperty("title"));
            props.Add("homedirectory", entry.GetProperty("homedirectory"));
            props.Add("description", entry.GetProperty("description"));
            props.Add("userpassword", entry.GetProperty("userpassword"));

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
            
            var sh = entry.GetPropertyAsArrayOfBytes("sidhistory");
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

                var res = LDAPUtils.Instance.ResolveSidAndType(sSid, domain);

                sidHistoryPrincipals.Add(res);
            }
            
            userProps.SidHistory =sidHistoryPrincipals.ToArray(); 
            
            props.Add("sidhistory", sidHistoryList.ToArray());

            userProps.Props = props;

            return userProps;
        }

        public static async Task<ComputerProperties> ReadComputerProperties(SearchResultEntry entry)
        {
            var compProps = new ComputerProperties();
            var props = new Dictionary<string, object>();
            
            var uac = entry.GetProperty("useraccountcontrol");
            bool enabled, unconstrained, trustedToAuth;
            if (int.TryParse(uac, out var flag))
            {
                var flags = (UAC.UacFlags)flag;
                enabled = (flags & UAC.UacFlags.AccountDisable) == 0;
                unconstrained = (flags & UAC.UacFlags.TrustedForDelegation) == UAC.UacFlags.TrustedForDelegation;
                trustedToAuth = (flags & UAC.UacFlags.TrustedToAuthForDelegation) != 0;
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
                var delegates = entry.GetPropertyAsArray("msds-allowedToDelegateTo");
                props.Add("allowedtodelegate", delegates);

                foreach (var d in delegates)
                {
                    var hname = d.Contains("/") ? d.Split('/')[1] : d;
                    hname = hname.Split(':')[0];
                    var resolvedHost = await LDAPUtils.Instance.ResolveHostToSid(hname, domain);
                    if (resolvedHost.Contains(".") || resolvedHost.Contains("S-1"))
                    {
                        comps.Add(new TypedPrincipal
                        {
                            ObjectIdentifier = resolvedHost,
                            ObjectType = Label.Computer
                        });
                    }
                }
            }

            compProps.AllowedToDelegate = comps.ToArray();

            var allowedToActPrincipals = new List<TypedPrincipal>();
            var rawAllowedToAct = entry.GetPropertyAsBytes("msDS-AllowedToActOnBehalfOfOtherIdentity");
            if (rawAllowedToAct != null)
            {
                var sd = new ActiveDirectorySecurity();
                sd.SetSecurityDescriptorBinaryForm(rawAllowedToAct, AccessControlSections.Access);
                foreach (ActiveDirectoryAccessRule rule in sd.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                {
                    var res = LDAPUtils.Instance.ResolveSidAndType(rule.IdentityReference.Value, domain);
                    allowedToActPrincipals.Add(res);
                }
            }

            compProps.AllowedToAct = allowedToActPrincipals.ToArray();

            props.Add("enabled", enabled);
            props.Add("unconstraineddelegation", unconstrained);
            props.Add("lastlogon", Helpers.ConvertToUnixEpoch(entry.GetProperty("lastlogon")));
            props.Add("lastlogontimestamp", Helpers.ConvertToUnixEpoch(entry.GetProperty("lastlogontimestamp")));
            props.Add("pwdlastset", Helpers.ConvertToUnixEpoch(entry.GetProperty("pwdlastset")));
            props.Add("serviceprincipalnames", entry.GetPropertyAsArray("serviceprincipalname"));
            var os = entry.GetProperty("operatingsystem");
            var sp = entry.GetProperty("operatingsystemservicepack");

            if (sp != null)
            {
                os = $"{os} {sp}";
            }

            props.Add("operatingsystem", os);
            props.Add("description", entry.GetProperty("description"));
            
            var sh = entry.GetPropertyAsArrayOfBytes("sidhistory");
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

                var res = LDAPUtils.Instance.ResolveSidAndType(sSid, domain);

                sidHistoryPrincipals.Add(res);
            }

            compProps.SidHistory = sidHistoryPrincipals.ToArray();

            props.Add("sidhistory", sidHistoryList.ToArray());

            compProps.Props = props;

            return compProps;
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
}