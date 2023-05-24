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

        /// <summary>
        /// This function should be called with the security data fetched from <see cref="GetCARegistryValues"/>.
        /// The resulting ACEs will contain the owner of the CA as well as Management rights.
        /// </summary>
        /// <param name="security"></param>
        /// <param name="objectDomain"></param>
        /// <param name="computerName"></param>
        /// <returns></returns>
        public IEnumerable<ACE> ProcessCAPermissions(byte[] security, string objectDomain, string computerName, bool fromRegistry)
        {
            if (security == null)
                yield break;

            var descriptor = _utils.MakeSecurityDescriptor();
            descriptor.SetSecurityDescriptorBinaryForm(security, AccessControlSections.All);

            var ownerSid = Helpers.PreProcessSID(descriptor.GetOwner(typeof(SecurityIdentifier)));

            if (ownerSid != null)
            {
                var resolvedOwner = fromRegistry ? GetRegistryPrincipal(new SecurityIdentifier(ownerSid), objectDomain, computerName) : _utils.ResolveIDAndType(ownerSid, objectDomain);
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
                _log.LogDebug("Owner on CA {Name} is null", computerName);
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
                var resolvedPrincipal = fromRegistry ? GetRegistryPrincipal(new SecurityIdentifier(principalSid), objectDomain, computerName) : _utils.ResolveIDAndType(principalSid, principalDomain);

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
        /// This function should be called with the enrollment data fetched from <see cref="GetCARegistryValues"/>.
        /// The resulting items will contain enrollment agent restrictions
        /// </summary>
        /// <param name="enrollmentAgentRestrictions"></param>
        /// <returns></returns>
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
        
        /// <summary>
        /// Get CA security regitry value from the remote machine for processing security/enrollmentagentrights
        /// </summary>
        /// <param name="target"></param>
        /// <param name="caName"></param>
        /// <returns></returns>
        [ExcludeFromCodeCoverage]
        public byte[] GetCASecurity(string target, string caName)
        {
            var regSubKey = $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{caName}";
            var regValue = "Security";
            try
            {
                var baseKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, target);
                var key = baseKey.OpenSubKey(regSubKey);
                return (byte[])key?.GetValue(regValue);
            }
            catch (Exception e)
            {
                _log.LogError(e, "Error getting data from registry for {CA} on {Target}: {RegSubKey}:{RegValue}", caName, target, regSubKey, regValue);
                return null;
            }
        }

        /// <summary>
        /// Get EnrollmentAgentRights regitry value from the remote machine for processing security/enrollmentagentrights
        /// </summary>
        /// <param name="target"></param>
        /// <param name="caName"></param>
        /// <returns></returns>
        [ExcludeFromCodeCoverage]
        public byte[] GetEnrollmentAgentRights(string target, string caName)
        {
            var regSubKey = $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{caName}";
            var regValue = "EnrollmentAgentRights";
            try
            {
                var baseKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, target);
                var key = baseKey.OpenSubKey(regSubKey);
                return (byte[])key?.GetValue(regValue);
            }
            catch (Exception e)
            {
                _log.LogError(e, "Error getting data from registry for {CA} on {Target}: {RegSubKey}:{RegValue}", caName, target, regSubKey, regValue);
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

        private TypedPrincipal GetRegistryPrincipal(SecurityIdentifier securityIdentifier, string computerDomain, string computerName)
        {
            // Check if the sid is one of our filtered ones. Throw it out if it is
            if (Helpers.IsSidFiltered(securityIdentifier.Value))
                return null;

            // Check if domain sid and attempt to resolve
            if (securityIdentifier.Value.StartsWith("S-1-5-21-"))
                return _utils.ResolveIDAndType(securityIdentifier.Value, computerDomain);

            // At this point, the sid is local principal on the CA server. If the CA is also a DC, the local principal is should be converted to a domain principal by post processing.
            return new TypedPrincipal
            {
                ObjectIdentifier = $"{computerName}-{securityIdentifier.Value}",
                ObjectType = Label.Base
            };
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
}