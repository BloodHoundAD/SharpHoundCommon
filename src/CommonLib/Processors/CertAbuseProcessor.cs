using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib.Processors
{
    public class CertAbuseProcessor
    {
        private readonly ILogger _log;
        private readonly ILDAPUtils _utils;
        
        public CertAbuseProcessor(ILDAPUtils utils, ILogger log = null)
        {
            _utils = utils;
            _log = log ?? Logging.LogProvider.CreateLogger("CAProc");
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
                _log.LogDebug("Owner on CA is null");
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
        
        /// <summary>
        /// Gets 2 specific registry keys from the remote machine for processing security/enrollmentagentrights
        /// </summary>
        /// <param name="target"></param>
        /// <param name="caName"></param>
        /// <returns></returns>
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
                _log.LogError(e, "Error getting data from registry for {CA} on {Target}", caName, target);
                return null;
            }
        }
        
        /// <summary>
        /// This function checks a registry setting on the target host for the specified CA to see if a requesting user can specify any SAN they want, which overrides template settings.
        /// The ManageCA permission allows you to flip this bit as well. This appears to usually work, even if admin rights aren't available on the remote CA server
        /// </summary>
        /// <remarks>https://blog.keyfactor.com/hidden-dangers-certificate-subject-alternative-names-sans</remarks>
        /// <param name="target"></param>
        /// <param name="caName"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        [ExcludeFromCodeCoverage]
        public bool IsUserSpecifiesSanEnabled(string target, string caName)
        {
            try
            {
                var baseKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, target);
                var key = baseKey.OpenSubKey(
                    $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{caName}\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy");
                if (key == null)
                {
                    _log.LogError("Registry key for IsUserSpecifiesSanEnabled is null from {CA} on {Target}", caName, target);
                    return false;
                }
                var editFlags = (int)key.GetValue("EditFlags");
                // 0x00040000 -> EDITF_ATTRIBUTESUBJECTALTNAME2
                return (editFlags & 0x00040000) == 0x00040000;
            }
            catch (Exception e)
            {
                _log.LogError(e, "Error getting IsUserSpecifiesSanEnabled from {CA} on {Target}", caName, target);
                return false;
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