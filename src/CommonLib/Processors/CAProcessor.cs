using System;
using System.Collections.Generic;
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
                }else if ((rights & CertificationAuthorityRights.ManageCertificates) != 0)
                {
                    yield return new ACE
                    {
                        IsInherited = false,
                        PrincipalType = resolvedPrincipal.ObjectType,
                        PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                        RightName = EdgeNames.ManageCertificates
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
                return null;
            }
        }
    }
}