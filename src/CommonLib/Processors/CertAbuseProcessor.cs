using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.LDAPQueries;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib.Processors
{
    public class CertAbuseProcessor
    {
        public const string EnterpriseCALocation = "CN=Enrollment Services,CN=Public Key Services,CN=Services,";
        public const string RootCALocation = "CN=Certification Authorities,CN=Public Key Services,CN=Services,";
        public const string CertTemplateLocation = "CN=Certificate Templates,CN=Public Key Services,CN=Services,";
        public const string NTAuthCertificateLocation = "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,";

        private readonly ILDAPUtils _utils;

        public CertAbuseProcessor(ILDAPUtils utils)
        {
            _utils = utils;
        }

        public IEnumerable<RootCA> GetRootCAs(string domain)
        {
            if (!_utils.IsForestRoot(domain))
                yield break;

            var configurationPath = _utils.GetConfigurationPath(domain);
            if (configurationPath == null)
                yield break;

            var query = new LDAPFilter();
            query.AddCertificateAuthorities();
            foreach (var rootCAEntry in _utils
                .QueryLDAP(query.GetFilter(), SearchScope.Base, new[] { "objectguid", "cacertificate" },
                    adsPath: $"{NTAuthCertificateLocation}{configurationPath}"))
            {
                var guid = rootCAEntry.GetObjectIdentifier();
                var rawCertificate = rootCAEntry.GetByteProperty("cacertificate");
                if (guid != null)
                {
                    var rootCa = new RootCA
                    {
                        ObjectIdentifier = guid
                    };

                    if (rawCertificate != null)
                        rootCa.Certificate = new Certificate(rawCertificate);
                    yield return rootCa;
                }
            }
        }

        public IEnumerable<Certificate> GetTrustedCerts(string domain)
        {
            if (!_utils.IsForestRoot(domain))
                return Array.Empty<Certificate>();

            var configurationPath = _utils.GetConfigurationPath(domain);
            if (configurationPath == null)
                return Array.Empty<Certificate>();

            var query = new LDAPFilter();
            query.AddCertificateAuthorities();
            var ntAuthCert = _utils
                .QueryLDAP(query.GetFilter(), SearchScope.Base, new[] { "cacertificate" },
                    adsPath: $"{NTAuthCertificateLocation}{configurationPath}").DefaultIfEmpty(null).FirstOrDefault();

            if (ntAuthCert == null)
                return Array.Empty<Certificate>();

            return ntAuthCert.GetByteArrayProperty("cacertificate").Select(x => new Certificate(x));
        }

        public IEnumerable<TypedPrincipal> ResolveTemplates(string[] templateNames, string objectDomain)
        {
            if (templateNames == null || templateNames.Length == 0)
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
                    yield return new ACE
                    {
                        PrincipalType = resolvedOwner.ObjectType,
                        PrincipalSID = resolvedOwner.ObjectIdentifier,
                        RightName = EdgeNames.Owns,
                        IsInherited = false
                    };
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

                var rights = (CertificationAuthorityRights)rule.ActiveDirectoryRights();

                if ((rights & CertificationAuthorityRights.ManageCA) != 0)
                    yield return new ACE
                    {
                        IsInherited = false,
                        PrincipalType = resolvedPrincipal.ObjectType,
                        PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                        RightName = EdgeNames.ManageCA
                    };
                if ((rights & CertificationAuthorityRights.ManageCertificates) != 0)
                    yield return new ACE
                    {
                        IsInherited = false,
                        PrincipalType = resolvedPrincipal.ObjectType,
                        PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                        RightName = EdgeNames.ManageCertificates
                    };

                if ((rights & CertificationAuthorityRights.Enroll) != 0)
                    yield return new ACE
                    {
                        IsInherited = false,
                        PrincipalType = resolvedPrincipal.ObjectType,
                        PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                        RightName = EdgeNames.Enroll
                    };
            }
        }

        // IRegistryKey version for testing if we decide to write tests for this
        // public CARegistryValues GetCARegistryValues(IRegistryKey registryKey, string caName)
        // {
        //     try
        //     {
        //         registryKey.OpenSubKey($"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{caName}");
        //         var values = new CARegistryValues
        //         {
        //             CASecurity = (byte[])registryKey.GetValue("Security"),
        //             EASecurity = (byte[])registryKey.GetValue("EnrollmentAgentRights")
        //         };
        //
        //         return values;
        //     }
        //     catch (Exception e)
        //     {
        //         Logging.Log(LogLevel.Error, "Error getting data from registry: {error}", e);
        //         return null;
        //     }
        // }

        [ExcludeFromCodeCoverage]
        public CARegistryValues GetCARegistryValues(string target, string caName)
        {
            try
            {
                var baseKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, target);
                var key = baseKey.OpenSubKey($"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{caName}");
                var values = new CARegistryValues
                {
                    CASecurity = (byte[])key?.GetValue("Security"),
                    EASecurity = (byte[])key?.GetValue("EnrollmentAgentRights")
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
        [ExcludeFromCodeCoverage]
        public bool IsUserSpecifiesSanEnabled(string target, string caName)
        {
            // ref- https://blog.keyfactor.com/hidden-dangers-certificate-subject-alternative-names-sans
            //  NOTE: this appears to usually work, even if admin rights aren't available on the remote CA server
            int editFlags;
            try
            {
                var baseKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, target);
                var key = baseKey.OpenSubKey(
                    $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{caName}\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy");
                editFlags = (int)key.GetValue("EditFlags");
                // 0x00040000 -> EDITF_ATTRIBUTESUBJECTALTNAME2
                return (editFlags & 0x00040000) == 0x00040000;
            }
            catch (Exception e)
            {
                throw new Exception("Error getting data from registry: {error}", e);
            }
        }
    }

    public class EnrollmentAgentRestriction
    {
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
                Template = Encoding.Unicode.GetString(opaque, index, opaque.Length - index - 2)
                    .Replace("\u0000", string.Empty);
            else
                Template = "<All>";

            Targets = targets.ToArray();
        }

        public string Agent { get; set; }
        public string Template { get; set; }
        public string[] Targets { get; set; }
    }

    public class CARegistryValues
    {
        public byte[] CASecurity { get; set; }
        public byte[] EASecurity { get; set; }
    }
}