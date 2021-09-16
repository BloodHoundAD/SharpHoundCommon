using System;
using System.Collections.Generic;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib.Processors
{
    public class CAProcessor
    {
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

        public byte[] GetCASecurityFromRegistry(string target, string caName)
        {
            try
            {
                var baseKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, target);
                var key = baseKey.OpenSubKey($"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{caName}");
                return (byte[]) key?.GetValue("Security");
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
}