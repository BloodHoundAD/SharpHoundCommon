using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Threading.Tasks;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.LDAPQueries;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib.Processors
{
    public class LDAPPropertyProcessor
    {
        private static readonly string[] ReservedAttributes = CommonProperties.TypeResolutionProps
            .Concat(CommonProperties.BaseQueryProps).Concat(CommonProperties.GroupResolutionProps)
            .Concat(CommonProperties.ComputerMethodProps).Concat(CommonProperties.ACLProps)
            .Concat(CommonProperties.ObjectPropsProps).Concat(CommonProperties.ContainerProps)
            .Concat(CommonProperties.SPNTargetProps).Concat(CommonProperties.DomainTrustProps)
            .Concat(CommonProperties.GPOLocalGroupProps).ToArray();

        private readonly ILDAPUtils _utils;

        public LDAPPropertyProcessor(ILDAPUtils utils)
        {
            _utils = utils;
        }

        private static Dictionary<string, object> GetCommonProps(ISearchResultEntry entry)
        {
            var props = GetProperties(LDAPProperties.Description, entry);
            props.AddMany(GetProperties(LDAPProperties.WhenCreated, entry));
            return props;
        }

        /// <summary>
        ///     Reads specific LDAP properties related to Domains
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public static Dictionary<string, object> ReadDomainProperties(ISearchResultEntry entry)
        {
            var props = GetCommonProps(entry);
            props.AddMany(GetProperties(LDAPProperties.DomainFunctionalLevel, entry));

            return props;
        }

        /// <summary>
        ///     Reads specific LDAP properties related to GPOs
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public static Dictionary<string, object> ReadGPOProperties(ISearchResultEntry entry)
        {
            var props = GetCommonProps(entry);
            props.AddMany(GetProperties(LDAPProperties.GPCFileSYSPath, entry));
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
            props.AddMany(GetProperties(LDAPProperties.AdminCount, entry));

            return props;
        }

        /// <summary>
        ///     Reads specific LDAP properties related to containers
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public static Dictionary<string, object> ReadContainerProperties(ISearchResultEntry entry)
        {
            var props = GetCommonProps(entry);
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
            
            props.AddMany((GetProperties(LDAPProperties.AllowedToDelegateTo, entry)));
            userProps.AllowedToDelegate = (await ReadPropertyDelegates(entry)).ToArray();

            props.AddMany(GetProperties(LDAPProperties.UserAccountControl, entry));
            props.AddMany(GetProperties(LDAPProperties.LastLogon, entry));
            props.AddMany(GetProperties(LDAPProperties.LastLogonTimestamp, entry));
            props.AddMany(GetProperties(LDAPProperties.PasswordLastSet, entry));
            props.AddMany(GetProperties(LDAPProperties.ServicePrincipalNames, entry));
            props.AddMany(GetProperties(LDAPProperties.DisplayName, entry));
            props.AddMany(GetProperties(LDAPProperties.Email, entry));
            props.AddMany(GetProperties(LDAPProperties.Title, entry));
            props.AddMany(GetProperties(LDAPProperties.HomeDirectory, entry));
            props.AddMany(GetProperties(LDAPProperties.UserPassword, entry));
            props.AddMany(GetProperties(LDAPProperties.UnixUserPassword, entry));
            props.AddMany(GetProperties(LDAPProperties.UnicodePassword, entry));
            props.AddMany(GetProperties(LDAPProperties.MsSFU30Password, entry));
            props.AddMany(GetProperties(LDAPProperties.ScriptPath, entry));
            props.AddMany(GetProperties(LDAPProperties.AdminCount, entry));

            var sidHistory = ReadSidHistory(entry);
            props.Add(PropertyMap.GetPropertyName(LDAPProperties.SIDHistory), sidHistory.ToArray());
            userProps.SidHistory = sidHistory.Select(ssid => ReadSidPrinciple(entry, ssid)).ToArray();

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
            
            props.AddMany(GetProperties(LDAPProperties.UserAccountControl, entry));

            props.AddMany((GetProperties(LDAPProperties.AllowedToDelegateTo, entry)));
            compProps.AllowedToDelegate = (await ReadPropertyDelegates(entry)).ToArray();
            
            compProps.AllowedToAct = ReadAllowedToActPrinciples(entry).ToArray();

            props.AddMany(GetProperties(LDAPProperties.LastLogon, entry));
            props.AddMany(GetProperties(LDAPProperties.LastLogonTimestamp, entry));
            props.AddMany(GetProperties(LDAPProperties.PasswordLastSet, entry));
            props.AddMany(GetProperties(LDAPProperties.ServicePrincipalNames, entry));
            props.AddMany(GetProperties(LDAPProperties.Email, entry));
            props.AddMany(GetProperties(LDAPProperties.OperatingSystem, entry));

            var sidHistory = ReadSidHistory(entry);
            props.Add(PropertyMap.GetPropertyName(LDAPProperties.SIDHistory), sidHistory.ToArray());
            compProps.SidHistory = sidHistory.Select(ssid => ReadSidPrinciple(entry, ssid)).ToArray();
            
            compProps.DumpSMSAPassword = ReadSmsaPrinciples(entry).ToArray();

            compProps.Props = props;

            return compProps;
        }
        
        /// <summary>
        /// Reads principals user or computer may delegate.
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public async Task<List<TypedPrincipal>> ReadPropertyDelegates(ISearchResultEntry entry)
        {
            var comps = new List<TypedPrincipal>();
            
            var domain = Helpers.DistinguishedNameToDomain(entry.DistinguishedName);
            var uacFlags = GetUacFlags(entry);
            if (uacFlags[UacFlags.TrustedToAuthForDelegation])
            {
                var delegates = entry.GetArrayProperty(LDAPProperties.AllowedToDelegateTo);

                foreach (var d in delegates)
                {
                    if (d == null)
                        continue;

                    var resolvedHost = await _utils.ResolveHostToSid(d, domain);
                    if (resolvedHost != null && resolvedHost.Contains("S-1"))
                        comps.Add(new TypedPrincipal
                        {
                            ObjectIdentifier = resolvedHost,
                            ObjectType = Label.Computer
                        });
                }
            }

            return comps.Distinct().ToList();
        }

        /// <summary>
        /// Reads history of SIDs for domain object.
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public List<string> ReadSidHistory(ISearchResultEntry entry)
        {
            var domain = Helpers.DistinguishedNameToDomain(entry.DistinguishedName);
            var sh = entry.GetByteArrayProperty(LDAPProperties.SIDHistory);
            var sidHistoryList = new List<string>();
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
            }

            return sidHistoryList;
        }

        /// <summary>
        /// Get SID principal.
        /// </summary>
        /// <param name="entry"></param>
        /// <param name="sidHistoryItem"></param>
        /// <returns></returns>
        public TypedPrincipal ReadSidPrinciple(ISearchResultEntry entry, string sidHistoryItem)
        {
            var domain = Helpers.DistinguishedNameToDomain(entry.DistinguishedName);
            return _utils.ResolveIDAndType(sidHistoryItem, domain);
        }

        /// <summary>
        /// Read principals for identities domain object may act on behalf of.
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public List<TypedPrincipal> ReadAllowedToActPrinciples(ISearchResultEntry entry)
        {
            var allowedToActPrincipals = new List<TypedPrincipal>();
            
            var domain = Helpers.DistinguishedNameToDomain(entry.DistinguishedName);
            var rawAllowedToAct = entry.GetByteProperty(LDAPProperties.AllowedToActOnBehalfOfOtherIdentity);
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

            return allowedToActPrincipals;
        }

        /// <summary>
        /// Read Standalone Managed Service Accounts of domain object.
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public List<TypedPrincipal> ReadSmsaPrinciples(ISearchResultEntry entry)
        {
            var smsaPrincipals = new List<TypedPrincipal>();
            var hsa = entry.GetArrayProperty(LDAPProperties.HostServiceAccount);
            if (hsa != null)
            {
                foreach (var dn in hsa)
                {
                    var resolvedPrincipal = _utils.ResolveDistinguishedName(dn);

                    if (resolvedPrincipal != null)
                        smsaPrincipals.Add(resolvedPrincipal);
                }
            }

            return smsaPrincipals;
        }

        /// <summary>
        /// Returns the properties associated with the RootCA
        /// </summary>
        /// <param name="entry"></param>
        /// <returns>Returns a dictionary with the common properties of the RootCA</returns>
        public static Dictionary<string, object> ReadRootCAProperties(ISearchResultEntry entry)
        {
            var props = GetCommonProps(entry);

            // Certificate
            var rawCertificate = entry.GetByteProperty(LDAPProperties.CACertificate);
            if (rawCertificate != null)
            {
                ParsedCertificate cert = new ParsedCertificate(rawCertificate);
                props.Add("certthumbprint", cert.Thumbprint);
                props.Add("certname", cert.Name);
                props.Add("certchain", cert.Chain);
                props.Add("hasbasicconstraints", cert.HasBasicConstraints);
                props.Add("basicconstraintpathlength", cert.BasicConstraintPathLength);
            }

            return props;
        }

        /// <summary>
        /// Returns the properties associated with the AIACA
        /// </summary>
        /// <param name="entry"></param>
        /// <returns>Returns a dictionary with the common properties and the crosscertificatepair property of the AICA</returns>
        public static Dictionary<string, object> ReadAIACAProperties(ISearchResultEntry entry)
        {
            var props = GetCommonProps(entry);
            var crossCertificatePair = entry.GetByteArrayProperty((LDAPProperties.CrossCertificatePair));
            var hasCrossCertificatePair = crossCertificatePair.Length > 0;

            props.Add("crosscertificatepair", crossCertificatePair);
            props.Add("hascrosscertificatepair", hasCrossCertificatePair);

            // Certificate
            var rawCertificate = entry.GetByteProperty(LDAPProperties.CACertificate);
            if (rawCertificate != null)
            {
                ParsedCertificate cert = new ParsedCertificate(rawCertificate);
                props.Add("certthumbprint", cert.Thumbprint);
                props.Add("certname", cert.Name);
                props.Add("certchain", cert.Chain);
                props.Add("hasbasicconstraints", cert.HasBasicConstraints);
                props.Add("basicconstraintpathlength", cert.BasicConstraintPathLength);
            }

            return props;
        }

        public static Dictionary<string, object> ReadEnterpriseCAProperties(ISearchResultEntry entry)
        {
            var props = GetCommonProps(entry);
            if (entry.GetIntProperty("flags", out var flags)) props.Add("flags", (PKICertificateAuthorityFlags)flags);
            props.Add("caname", entry.GetProperty(LDAPProperties.Name));
            props.Add("dnshostname", entry.GetProperty(LDAPProperties.DNSHostName));

            // Certificate
            var rawCertificate = entry.GetByteProperty(LDAPProperties.CACertificate);
            if (rawCertificate != null)
            {
                ParsedCertificate cert = new ParsedCertificate(rawCertificate);
                props.Add("certthumbprint", cert.Thumbprint);
                props.Add("certname", cert.Name);
                props.Add("certchain", cert.Chain);
                props.Add("hasbasicconstraints", cert.HasBasicConstraints);
                props.Add("basicconstraintpathlength", cert.BasicConstraintPathLength);
            }

            return props;
        }

        /// <summary>
        /// Returns the properties associated with the NTAuthStore. These properties will only contain common properties
        /// </summary>
        /// <param name="entry"></param>
        /// <returns>Returns a dictionary with the common properties of the NTAuthStore</returns>
        public static Dictionary<string, object> ReadNTAuthStoreProperties(ISearchResultEntry entry)
        {
            var props = GetCommonProps(entry);
            return props;
        }

        /// <summary>
        /// Reads specific LDAP properties related to CertTemplates
        /// </summary>
        /// <param name="entry"></param>
        /// <returns>Returns a dictionary associated with the CertTemplate properties that were read</returns>
        public static Dictionary<string, object> ReadCertTemplateProperties(ISearchResultEntry entry)
        {
            var props = GetCommonProps(entry);

            props.Add("validityperiod", ConvertPKIPeriod(entry.GetByteProperty(LDAPProperties.PKIExpirationPeriod)));
            props.Add("renewalperiod", ConvertPKIPeriod(entry.GetByteProperty(LDAPProperties.PKIOverlappedPeriod)));

            if (entry.GetIntProperty(LDAPProperties.TemplateSchemaVersion, out var schemaVersion))
                props.Add("schemaversion", schemaVersion);

            props.Add("displayname", entry.GetProperty(LDAPProperties.DisplayName));
            props.Add("oid", entry.GetProperty(LDAPProperties.CertTemplateOID));

            if (entry.GetIntProperty(LDAPProperties.PKIEnrollmentFlag, out var enrollmentFlagsRaw))
            {
                var enrollmentFlags = (PKIEnrollmentFlag)enrollmentFlagsRaw;

                props.Add("enrollmentflag", enrollmentFlags);
                props.Add("requiresmanagerapproval", enrollmentFlags.HasFlag(PKIEnrollmentFlag.PEND_ALL_REQUESTS));
                props.Add("nosecurityextension", enrollmentFlags.HasFlag(PKIEnrollmentFlag.NO_SECURITY_EXTENSION));
            }

            if (entry.GetIntProperty(LDAPProperties.PKINameFlag, out var nameFlagsRaw))
            {
                var nameFlags = (PKICertificateNameFlag)nameFlagsRaw;

                props.Add("certificatenameflag", nameFlags);
                props.Add("enrolleesuppliessubject",
                    nameFlags.HasFlag(PKICertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT));
                props.Add("subjectaltrequireupn",
                    nameFlags.HasFlag(PKICertificateNameFlag.SUBJECT_ALT_REQUIRE_UPN));
                props.Add("subjectaltrequiredns",
                    nameFlags.HasFlag(PKICertificateNameFlag.SUBJECT_ALT_REQUIRE_DNS));
                props.Add("subjectaltrequiredomaindns",
                    nameFlags.HasFlag(PKICertificateNameFlag.SUBJECT_ALT_REQUIRE_DOMAIN_DNS));
                props.Add("subjectaltrequireemail",
                    nameFlags.HasFlag(PKICertificateNameFlag.SUBJECT_ALT_REQUIRE_EMAIL));
                props.Add("subjectaltrequirespn",
                    nameFlags.HasFlag(PKICertificateNameFlag.SUBJECT_ALT_REQUIRE_SPN));
                props.Add("subjectrequireemail",
                    nameFlags.HasFlag(PKICertificateNameFlag.SUBJECT_REQUIRE_EMAIL));
            }

            string[] ekus = entry.GetArrayProperty(LDAPProperties.ExtendedKeyUsage);
            props.Add("ekus", ekus);
            string[] certificateapplicationpolicy = entry.GetArrayProperty(LDAPProperties.CertificateApplicationPolicy);
            props.Add("certificateapplicationpolicy", certificateapplicationpolicy);

            if (entry.GetIntProperty(LDAPProperties.NumSignaturesRequired, out var authorizedSignatures))
                props.Add("authorizedsignatures", authorizedSignatures);

            props.Add("applicationpolicies", entry.GetArrayProperty(LDAPProperties.ApplicationPolicies));
            props.Add("issuancepolicies", entry.GetArrayProperty(LDAPProperties.IssuancePolicies));


            // Construct effectiveekus
            string[] effectiveekus = schemaVersion == 1 & ekus.Length > 0 ? ekus : certificateapplicationpolicy;
            props.Add("effectiveekus", effectiveekus);

            // Construct authenticationenabled
            bool authenticationenabled = effectiveekus.Intersect(Helpers.AuthenticationOIDs).Any() | effectiveekus.Length == 0;
            props.Add("authenticationenabled", authenticationenabled);

            return props;
        }

        /// <summary>
        ///     Attempts to parse all LDAP attributes outside of the ones already collected and converts them to a human readable
        ///     format using a best guess
        /// </summary>
        /// <param name="entry"></param>
        public Dictionary<string, object> ParseAllProperties(ISearchResultEntry entry)
        {
            var props = new Dictionary<string, object>();

            var type = typeof(LDAPProperties);
            var reserved = type.GetFields(BindingFlags.Static | BindingFlags.Public).Select(x => x.GetValue(null).ToString()).ToArray();

            foreach (var property in entry.PropertyNames())
            {
                if (ReservedAttributes.Contains(property, StringComparer.OrdinalIgnoreCase))
                    continue;

                var collCount = entry.PropCount(property);
                if (collCount == 0)
                    continue;

                if (collCount == 1)
                {
                    var testBytes = entry.GetByteProperty(property);

                    if (testBytes == null || testBytes.Length == 0) continue;

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
                    if (arrBytes.Length == 0)
                        continue;

                    var arr = entry.GetArrayProperty(property);
                    if (arr.Length > 0) props.Add(property, arr.Select(BestGuessConvert).ToArray());
                }
            }

            return props;
        }
        
        public static Dictionary<string, object> GetProperties(string ldapProperty, ISearchResultEntry entry)
        {
            var props = new Dictionary<string, object>();
            switch (ldapProperty)
            {
                case LDAPProperties.Description:
                    props.Add(PropertyMap.GetPropertyName(ldapProperty), entry.GetProperty(LDAPProperties.Description));
                    break;
                case LDAPProperties.WhenCreated:
                    props.Add(PropertyMap.GetPropertyName(ldapProperty), Helpers.ConvertTimestampToUnixEpoch(entry.GetProperty(LDAPProperties.WhenCreated)));
                    break;
                case LDAPProperties.DomainFunctionalLevel:
                    if (!int.TryParse(entry.GetProperty(LDAPProperties.DomainFunctionalLevel), out var level))
                        level = -1;
                    props.Add(PropertyMap.GetPropertyName(ldapProperty), FunctionalLevelToString(level));
                    break;
                case LDAPProperties.GPCFileSYSPath:
                    props.Add(PropertyMap.GetPropertyName(ldapProperty), entry.GetProperty(LDAPProperties.GPCFileSYSPath)?.ToUpper());
                    break;
                case LDAPProperties.LastLogon:
                    props.Add(PropertyMap.GetPropertyName(ldapProperty), Helpers.ConvertFileTimeToUnixEpoch(entry.GetProperty(LDAPProperties.LastLogon)));
                    break;
                case LDAPProperties.LastLogonTimestamp:
                    props.Add(PropertyMap.GetPropertyName(ldapProperty), Helpers.ConvertFileTimeToUnixEpoch(entry.GetProperty(LDAPProperties.LastLogonTimestamp)));
                    break;
                case LDAPProperties.PasswordLastSet:
                    props.Add(PropertyMap.GetPropertyName(ldapProperty), Helpers.ConvertFileTimeToUnixEpoch(entry.GetProperty(LDAPProperties.PasswordLastSet)));
                    break;
                case LDAPProperties.ServicePrincipalNames:
                    var spn = entry.GetArrayProperty(LDAPProperties.ServicePrincipalNames);
                    props.Add(PropertyMap.GetPropertyName(ldapProperty), spn);
                    props.Add("hasspn", spn.Length > 0);
                    break;
                case LDAPProperties.DisplayName:
                    props.Add(PropertyMap.GetPropertyName(ldapProperty), entry.GetProperty(LDAPProperties.DisplayName));
                    break;
                case LDAPProperties.Email:
                    props.Add(PropertyMap.GetPropertyName(ldapProperty), entry.GetProperty(LDAPProperties.Email));
                    break;
                case LDAPProperties.Title:
                    props.Add(PropertyMap.GetPropertyName(ldapProperty), entry.GetProperty(LDAPProperties.Title));
                    break;
                case LDAPProperties.HomeDirectory:
                    props.Add(PropertyMap.GetPropertyName(ldapProperty), entry.GetProperty(LDAPProperties.HomeDirectory));
                    break;
                case LDAPProperties.UserPassword:
                    props.Add(PropertyMap.GetPropertyName(ldapProperty), entry.GetProperty(LDAPProperties.UserPassword));
                    break;
                case LDAPProperties.UnixUserPassword:
                    props.Add(PropertyMap.GetPropertyName(ldapProperty), entry.GetProperty(LDAPProperties.UnixUserPassword));
                    break;
                case LDAPProperties.UnicodePassword:
                    props.Add(PropertyMap.GetPropertyName(ldapProperty), entry.GetProperty(LDAPProperties.UnicodePassword));
                    break;
                case LDAPProperties.MsSFU30Password:
                    props.Add(PropertyMap.GetPropertyName(ldapProperty), entry.GetProperty(LDAPProperties.MsSFU30Password));
                    break;
                case LDAPProperties.ScriptPath:
                    props.Add(PropertyMap.GetPropertyName(ldapProperty), entry.GetProperty(LDAPProperties.ScriptPath));
                    break;
                case LDAPProperties.AdminCount:
                    var ac = entry.GetProperty(LDAPProperties.AdminCount);
                    if (ac != null)
                    {
                        int.TryParse(ac, out var a);
                        props.Add(PropertyMap.GetPropertyName(ldapProperty), a != 0);
                    }
                    else
                    {
                        props.Add(PropertyMap.GetPropertyName(ldapProperty), false);
                    }
                    break;
                case LDAPProperties.UserAccountControl:
                    var allFlags = GetUacFlags(entry);
                    props.Add(PropertyMap.GetUacPropertyName(UacFlags.NotDelegated), allFlags[UacFlags.NotDelegated]);
                    props.Add(PropertyMap.GetUacPropertyName(UacFlags.DontReqPreauth), allFlags[UacFlags.DontReqPreauth]);
                    props.Add(PropertyMap.GetUacPropertyName(UacFlags.PasswordNotRequired), allFlags[UacFlags.PasswordNotRequired]);
                    props.Add(PropertyMap.GetUacPropertyName(UacFlags.TrustedForDelegation), allFlags[UacFlags.TrustedForDelegation]);
                    props.Add(PropertyMap.GetUacPropertyName(UacFlags.DontExpirePassword), allFlags[UacFlags.DontExpirePassword]);
                    // Note that we flip the flag for Account Disable ("enabled" by resolved name)
                    props.Add(PropertyMap.GetUacPropertyName(UacFlags.AccountDisable), !allFlags[UacFlags.AccountDisable]);
                    props.Add(PropertyMap.GetUacPropertyName(UacFlags.TrustedToAuthForDelegation), allFlags[UacFlags.TrustedToAuthForDelegation]);
                    props.Add(PropertyMap.GetUacPropertyName(UacFlags.ServerTrustAccount), allFlags[UacFlags.ServerTrustAccount]);
                    break;
                case LDAPProperties.OperatingSystem:
                    var os = entry.GetProperty(LDAPProperties.OperatingSystem);
                    var sp = entry.GetProperty(LDAPProperties.ServicePack);
                    if (sp != null) os = $"{os} {sp}";
                    props.Add(PropertyMap.GetPropertyName(ldapProperty), os);
                    break;
                case LDAPProperties.AllowedToDelegateTo:
                    var delegates = entry.GetArrayProperty(LDAPProperties.AllowedToDelegateTo);
                    props.Add(PropertyMap.GetPropertyName(ldapProperty), delegates);
                    break;
                
                default:
                    throw new ArgumentException("Cannot resolve to output property name.", ldapProperty);
            }

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
        /// Returns all flags of User Account Control and whether or not they're active.
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public static Dictionary<UacFlags, bool> GetUacFlags(ISearchResultEntry entry)
        {
            var props = new Dictionary<string, object>();

            var uacFlags = (UacFlags)0;
            var uac = entry.GetProperty(LDAPProperties.UserAccountControl);
            if (int.TryParse(uac, out var flags))
            {
                uacFlags = (UacFlags)flags;
            }

            return ReadFlags(uacFlags);
        }
        
        /// <summary>
        /// Get all flags of a domain object by enumeration.
        /// </summary>
        /// <param name="flags"></param>
        /// <typeparam name="T"></typeparam>
        /// <returns></returns>
        private static Dictionary<T, bool> ReadFlags<T>(T flags)
            where T : Enum
        {
            return Enum.GetValues(typeof(T))
                .Cast<T>()
                .ToDictionary(
                    val => val,
                    val => flags.HasFlag(val)
                );
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

            //Try parsing as an int
            if (int.TryParse(property, out var num)) return num;

            //Just return the property as a string
            return property;
        }

        /// <summary>
        ///     Converts PKIExpirationPeriod/PKIOverlappedPeriod attributes to time approximate times
        /// </summary>
        /// <remarks>https://www.sysadmins.lv/blog-en/how-to-convert-pkiexirationperiod-and-pkioverlapperiod-active-directory-attributes.aspx</remarks>
        /// <param name="bytes"></param>
        /// <returns>Returns a string representing the time period associated with the input byte array in a human readable form</returns>
        private static string ConvertPKIPeriod(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0)
                return "Unknown";

            try
            {
                Array.Reverse(bytes);
                var temp = BitConverter.ToString(bytes).Replace("-", "");
                var value = Convert.ToInt64(temp, 16) * -.0000001;

                if (value % 31536000 == 0 && value / 31536000 >= 1)
                {
                    if (value / 31536000 == 1) return "1 year";

                    return $"{value / 31536000} years";
                }

                if (value % 2592000 == 0 && value / 2592000 >= 1)
                {
                    if (value / 2592000 == 1) return "1 month";

                    return $"{value / 2592000} months";
                }

                if (value % 604800 == 0 && value / 604800 >= 1)
                {
                    if (value / 604800 == 1) return "1 week";

                    return $"{value / 604800} weeks";
                }

                if (value % 86400 == 0 && value / 86400 >= 1)
                {
                    if (value / 86400 == 1) return "1 day";

                    return $"{value / 86400} days";
                }

                if (value % 3600 == 0 && value / 3600 >= 1)
                {
                    if (value / 3600 == 1) return "1 hour";

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

    /// <summary>
    /// Provides single-truth mapping of domain object properties.
    /// </summary>
    public static class PropertyMap
    {
        /// <summary>
        /// Get output name of a domain object property.
        /// </summary>
        /// <param name="ldapProperty"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        public static string GetPropertyName(string ldapProperty)
        {
            switch (ldapProperty)
            {
                case LDAPProperties.Description:
                    return "description";
                case LDAPProperties.WhenCreated:
                    return "whencreated";
                case LDAPProperties.DomainFunctionalLevel:
                    return "functionallevel";
                case LDAPProperties.GPCFileSYSPath:
                    return "gpcpath";
                case LDAPProperties.LastLogon:
                    return "lastlogon";
                case LDAPProperties.LastLogonTimestamp:
                    return "lastlogontimestamp";
                case LDAPProperties.PasswordLastSet:
                    return "pwdlastset";
                case LDAPProperties.ServicePrincipalNames:
                    return "serviceprinciplenames";
                case LDAPProperties.DisplayName:
                    return "displayname";
                case LDAPProperties.Email:
                    return "email";
                case LDAPProperties.Title:
                    return "title";
                case LDAPProperties.HomeDirectory:
                    return "homedirectory";
                case LDAPProperties.UserPassword:
                    return "userpassword";
                case LDAPProperties.UnixUserPassword:
                    return "unixpassword";
                case LDAPProperties.UnicodePassword:
                    return "unicodepassword";
                case LDAPProperties.MsSFU30Password:
                    return "sfupassword";
                case LDAPProperties.ScriptPath:
                    return "logonscript";
                case LDAPProperties.AdminCount:
                    return "admincount";
                case LDAPProperties.OperatingSystem:
                    return "operatingsystem";
                case LDAPProperties.AllowedToDelegateTo:
                    return "allowedtodelegate";
                case LDAPProperties.SIDHistory:
                    return "sidhistory";
                
                default:
                    throw new ArgumentException("Cannot resolve to output property name.", ldapProperty);
            }
        }

        public static string GetUacPropertyName(UacFlags flag)
        {
            switch (flag)
            {
                case UacFlags.NotDelegated:
                    return "sensitive";
                case UacFlags.DontReqPreauth:
                    return "dontreqpreauth";
                case UacFlags.PasswordNotRequired:
                    return "passwordnotreqd";
                case UacFlags.TrustedForDelegation:
                    return "unconstraineddelegation";
                case UacFlags.DontExpirePassword:
                    return "pwdneverexpires";
                // Note that we flip the flag for output
                case UacFlags.AccountDisable:
                    return "enabled";
                case UacFlags.TrustedToAuthForDelegation:
                    return "trustedtoauth";
                case UacFlags.ServerTrustAccount:
                    return "isdc";
                
                default:
                    throw new ArgumentException("Cannot resolve to output property name.", Enum.GetName(typeof(UacFlags), flag));
            }
        }
    }

    public class ParsedCertificate
    {
        public string Thumbprint { get; set; }
        public string Name { get; set; }
        public string[] Chain { get; set; } = Array.Empty<string>();
        public bool HasBasicConstraints { get; set; } = false;
        public int BasicConstraintPathLength { get; set; }

        public ParsedCertificate(byte[] rawCertificate)
        {
            var parsedCertificate = new X509Certificate2(rawCertificate);
            Thumbprint = parsedCertificate.Thumbprint;
            var name = parsedCertificate.FriendlyName;
            Name = string.IsNullOrEmpty(name) ? Thumbprint : name;

            // Chain
            X509Chain chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.Build(parsedCertificate);
            var temp = new List<string>();
            foreach (X509ChainElement cert in chain.ChainElements) temp.Add(cert.Certificate.Thumbprint);
            Chain = temp.ToArray();

            // Extensions
            X509ExtensionCollection extensions = parsedCertificate.Extensions;
            List<CertificateExtension> certificateExtensions = new List<CertificateExtension>();
            foreach (X509Extension extension in extensions)
            {
                CertificateExtension certificateExtension = new CertificateExtension(extension);
                switch (certificateExtension.Oid.Value)
                {
                    case CAExtensionTypes.BasicConstraints:
                        X509BasicConstraintsExtension ext = (X509BasicConstraintsExtension)extension;
                        HasBasicConstraints = ext.HasPathLengthConstraint;
                        BasicConstraintPathLength = ext.PathLengthConstraint;
                        break;
                }
            }
        }
    }

    public class UserProperties
    {
        public Dictionary<string, object> Props { get; set; } = new();
        public TypedPrincipal[] AllowedToDelegate { get; set; } = Array.Empty<TypedPrincipal>();
        public TypedPrincipal[] SidHistory { get; set; } = Array.Empty<TypedPrincipal>();
    }

    public class ComputerProperties
    {
        public Dictionary<string, object> Props { get; set; } = new();
        public TypedPrincipal[] AllowedToDelegate { get; set; } = Array.Empty<TypedPrincipal>();
        public TypedPrincipal[] AllowedToAct { get; set; } = Array.Empty<TypedPrincipal>();
        public TypedPrincipal[] SidHistory { get; set; } = Array.Empty<TypedPrincipal>();
        public TypedPrincipal[] DumpSMSAPassword { get; set; } = Array.Empty<TypedPrincipal>();
    }
}
