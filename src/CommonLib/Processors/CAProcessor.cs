using System;
using System.Collections.Generic;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib.Processors
{
    public class CAProcessor
    {
        public const string EnterpriseCALocation = "CN=Enrollment Services,CN=Public Key Services,CN=Services,";
        public const string RootCALocation = "CN=Certification Authorities,CN=Public Key Services,CN=Services,";
        public const string CertTemplateLocation = "CN=Certificate Templates,CN=Public Key Services,CN=Services,";
        public const string NTAuthCertificateLocation = "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,";
        
        private readonly ILDAPUtils _utils;

        public CAProcessor(ILDAPUtils utils)
        {
            _utils = utils;
        }

        public IEnumerable<TypedPrincipal> ResolveTemplates(string[] templateNames, string objectDomain)
        {
            if (templateNames == null | templateNames.Length == 0)
                yield break;

            foreach (var template in templateNames)
            {
                var res = _utils.ResolveCertificateTemplate(template, objectDomain);
                if (res != null)
                    yield return res;
            }
        }

        public IEnumerable<EnrollmentAgentRestriction> ProcessEAPermissions(byte[] enrollmentAgentRestrictions)
        {
            if (enrollmentAgentRestrictions == null)
                yield break;

            var descriptor = new RawSecurityDescriptor(enrollmentAgentRestrictions, 0);
            foreach (var genericAce in descriptor.DiscretionaryAcl)
            {
                var ace = (QualifiedAce)genericAce;
                yield return new EnrollmentAgentRestriction(ace);
            }
        }

        public IEnumerable<ACE> ProcessCAPermissions(byte[] security, string objectDomain)
        {
            if (security == null)
                yield break;

            var descriptor = _utils.MakeSecurityDescriptor();
            descriptor.SetSecurityDescriptorBinaryForm(security, AccessControlSections.All);

            var ownerSid = Helpers.PreProcessSID(descriptor.GetOwner(typeof(SecurityIdentifier)));

            if (ownerSid != null)
            {
                var resolvedOwner = _utils.ResolveIDAndType(ownerSid, objectDomain);
                if (resolvedOwner != null)
                {
                    yield return new ACE
                    {
                        PrincipalType = resolvedOwner.ObjectType,
                        PrincipalSID = resolvedOwner.ObjectIdentifier,
                        RightName = EdgeNames.Owns,
                        IsInherited = false
                    };
                }
            }
            else
            {
                Logging.Log(LogLevel.Debug, "Owner on CA is null");
            }

            foreach (var rule in descriptor.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (rule == null)
                    continue;

                if (rule.AccessControlType() == AccessControlType.Deny)
                    continue;

                var principalSid = Helpers.PreProcessSID(rule.IdentityReference());
                if (principalSid == null)
                    continue;

                var principalDomain = _utils.GetDomainNameFromSid(principalSid) ?? objectDomain;
                var resolvedPrincipal = _utils.ResolveIDAndType(principalSid, principalDomain);
                
                var rights = (CertificationAuthorityRights) rule.ActiveDirectoryRights();

                if ((rights & CertificationAuthorityRights.ManageCA) != 0)
                {
                    yield return new ACE
                    {
                        IsInherited = false,
                        PrincipalType = resolvedPrincipal.ObjectType,
                        PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                        RightName = EdgeNames.ManageCA
                    };
                }
                if ((rights & CertificationAuthorityRights.ManageCertificates) != 0)
                {
                    yield return new ACE
                    {
                        IsInherited = false,
                        PrincipalType = resolvedPrincipal.ObjectType,
                        PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                        RightName = EdgeNames.ManageCertificates
                    };
                }

                if ((rights & CertificationAuthorityRights.Enroll) != 0)
                {
                    yield return new ACE
                    {
                        IsInherited = false,
                        PrincipalType = resolvedPrincipal.ObjectType,
                        PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                        RightName = EdgeNames.Enroll
                    };
                }
            }
        }

        public CARegistryValues GetCARegistryValues(string target, string caName)
        {
            try
            {
                var baseKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, target);
                var key = baseKey.OpenSubKey($"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{caName}");
                var values = new CARegistryValues
                {
                    CASecurity = (byte[]) key?.GetValue("Security"),
                    EASecurity = (byte[]) key?.GetValue("EnrollmentAgentRights")
                };

                return values;
            }
            catch (Exception e)
            {
                Logging.Log(LogLevel.Error, "Error getting data from registry: {error}", e);
                return null;
            }
        }

        // Registry setting. If flipped, for any published template the CA is serving, any requesting user can specify any SAN they want. Overrides template settings. ManageCA allows you to flip this bit. 
        // Also enumerate this on CAs. Still requires some other preconditions.
        public bool IsUserSpecifiesSanEnabled(string target, string caName)
        {
            // ref- https://blog.keyfactor.com/hidden-dangers-certificate-subject-alternative-names-sans
            //  NOTE: this appears to usually work, even if admin rights aren't available on the remote CA server
            RegistryKey baseKey;
            try
            {
                baseKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, target);
            }
            catch (Exception e)
            {
                throw new Exception($"Could not connect to the HKLM hive - {e.Message}");
            }

            int editFlags;
            try
            {
                var key = baseKey.OpenSubKey($"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{caName}\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy");
                editFlags = (int)key.GetValue("EditFlags");
            }
            catch (SecurityException e)
            {
                throw new Exception($"Could not access the EditFlags registry value: {e.Message}");
            }

            // 0x00040000 -> EDITF_ATTRIBUTESUBJECTALTNAME2
            return (editFlags & 0x00040000) == 0x00040000;
        }
    }

    public class EnrollmentAgentRestriction
    {
        public string Agent { get; set; }
        public string Template { get; set; }
        public string[] Targets { get; set; }

        public EnrollmentAgentRestriction(QualifiedAce ace)
        {
            var targets = new List<string>();
            var index = 0;
            Agent = ace.SecurityIdentifier.ToString().ToUpper();
            var opaque = ace.GetOpaque();
            var sidCount = BitConverter.ToUInt32(opaque, 0);
            index += 4;

            for (var i = 0; i < sidCount; i++)
            {
                var sid = new SecurityIdentifier(opaque, index);
                targets.Add(sid.ToString().ToUpper());
                index += sid.BinaryLength;
            }

            if (index < opaque.Length)
            {
                Template = Encoding.Unicode.GetString(opaque, index, (opaque.Length - index - 2)).Replace("\u0000", string.Empty);
            }
            else
            {
                Template = "<All>";
            }

            Targets = targets.ToArray();
        }
    }

    public class CARegistryValues
    {
        public byte[] CASecurity { get; set; }
        public byte[] EASecurity { get; set; }
    }
}