using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundRPC;
using SharpHoundRPC.Wrappers;

namespace SharpHoundCommonLib.Processors
{
    public class CertAbuseProcessor
    {
        private readonly ILogger _log;
        public readonly ILDAPUtils _utils;
        public delegate Task ComputerStatusDelegate(CSVComputerStatus status);
        public event ComputerStatusDelegate ComputerStatusEvent;

        
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
        public async Task<AceRegistryAPIResult> ProcessRegistryEnrollmentPermissions(string caName, string objectDomain, string computerName, string computerObjectId)
        {
            var data = new AceRegistryAPIResult();

            var aceData = GetCASecurity(computerName, caName);
            data.Collected = aceData.Collected;
            if (!aceData.Collected)
            {
                data.FailureReason = aceData.FailureReason;
                return data;
            }

            if (aceData.Value == null)
            {
                return data;
            }

            var descriptor = _utils.MakeSecurityDescriptor();
            descriptor.SetSecurityDescriptorBinaryForm(aceData.Value as byte[], AccessControlSections.All);

            var ownerSid = Helpers.PreProcessSID(descriptor.GetOwner(typeof(SecurityIdentifier)));
            var computerDomain = _utils.GetDomainNameFromSid(computerObjectId);
            var isDomainController = _utils.IsDomainController(computerObjectId, computerDomain);
            var machineSid = await GetMachineSid(computerName, computerObjectId, computerDomain, isDomainController);

            var aces = new List<ACE>();

            if (ownerSid != null)
            {
                var resolvedOwner = GetRegistryPrincipal(new SecurityIdentifier(ownerSid), computerDomain, computerName, isDomainController, computerObjectId, machineSid);
                if (resolvedOwner != null)
                    aces.Add(new ACE
                    {
                        PrincipalType = resolvedOwner.ObjectType,
                        PrincipalSID = resolvedOwner.ObjectIdentifier,
                        RightName = EdgeNames.Owns,
                        IsInherited = false
                    }); 
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
                var resolvedPrincipal = GetRegistryPrincipal(new SecurityIdentifier(principalSid), principalDomain, computerName, isDomainController, computerObjectId, machineSid);
                var isInherited = rule.IsInherited();

                var cARights = (CertificationAuthorityRights)rule.ActiveDirectoryRights();

                // TODO: These if statements are also present in ProcessACL. Move to shared location.               
                if ((cARights & CertificationAuthorityRights.ManageCA) != 0)
                    aces.Add(new ACE
                    {
                        PrincipalType = resolvedPrincipal.ObjectType,
                        PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                        IsInherited = isInherited,
                        RightName = EdgeNames.ManageCA
                    });
                if ((cARights & CertificationAuthorityRights.ManageCertificates) != 0)
                    aces.Add(new ACE
                    {
                        PrincipalType = resolvedPrincipal.ObjectType,
                        PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                        IsInherited = isInherited,
                        RightName = EdgeNames.ManageCertificates
                    });

                if ((cARights & CertificationAuthorityRights.Enroll) != 0)
                    aces.Add(new ACE
                    {
                        PrincipalType = resolvedPrincipal.ObjectType,
                        PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                        IsInherited = isInherited,
                        RightName = EdgeNames.Enroll
                    });
            }

            data.Data = aces.ToArray();
            return data;
        }
        
        /// <summary>
        /// This function should be called with the enrollment data fetched from <see cref="GetCARegistryValues"/>.
        /// The resulting items will contain enrollment agent restrictions
        /// </summary>
        /// <param name="enrollmentAgentRestrictions"></param>
        /// <returns></returns>
        public async Task<EnrollmentAgentRegistryAPIResult> ProcessEAPermissions(string caName, string objectDomain, string computerName, string computerObjectId)
        {
            var ret = new EnrollmentAgentRegistryAPIResult();
            var regData = GetEnrollmentAgentRights(computerName, caName);

            ret.Collected = regData.Collected;
            if (!ret.Collected)
            {
                ret.FailureReason = regData.FailureReason;
                return ret;
            }

            if (regData.Value == null)
            {
                return ret;
            }
            
            var computerDomain = _utils.GetDomainNameFromSid(computerObjectId);
            var isDomainController = _utils.IsDomainController(computerObjectId, computerDomain);
            var machineSid = await GetMachineSid(computerName, computerObjectId, computerDomain, isDomainController);
            var certTemplatesLocation = _utils.BuildLdapPath(DirectoryPaths.CertTemplateLocation, computerDomain);
            var descriptor = new RawSecurityDescriptor(regData.Value as byte[], 0);
            var enrollmentAgentRestrictions = new List<EnrollmentAgentRestriction>();
            foreach (var genericAce in descriptor.DiscretionaryAcl)
            {
                var ace = (QualifiedAce)genericAce;
                enrollmentAgentRestrictions.Add(new EnrollmentAgentRestriction(ace, computerDomain, certTemplatesLocation, this, computerName, isDomainController, computerObjectId, machineSid));
            }

            ret.Restrictions = enrollmentAgentRestrictions.ToArray();

            return ret;
        }
        
        public IEnumerable<TypedPrincipal> ProcessCertTemplates(string[] templates, string domainName)
        {
            var certTemplatesLocation = _utils.BuildLdapPath(DirectoryPaths.CertTemplateLocation, domainName);
            foreach (var templateCN in templates)
            {
                var res = _utils.ResolveCertTemplateByProperty(templateCN, LDAPProperties.CanonicalName, certTemplatesLocation, domainName);
                yield return res;
            }
        }

        public string GetCertThumbprint(byte[] rawCert)
        {
            var parsedCertificate = new X509Certificate2(rawCert);
            return parsedCertificate.Thumbprint;
        }

        /// <summary>
        /// Get CA security registry value from the remote machine for processing security/enrollmentagentrights
        /// </summary>
        /// <param name="target"></param>
        /// <param name="caName"></param>
        /// <returns></returns>
        [ExcludeFromCodeCoverage]
        private RegistryResult GetCASecurity(string target, string caName)
        {
            var regSubKey = $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{caName}";
            const string regValue = "Security";
        
            return GetRegistryKeyData(target, regSubKey, regValue);
        }

        public virtual IRegistryKey OpenRemoteRegistry(string target)
        {
            var key = new SHRegistryKey(RegistryHive.LocalMachine, target);
            return key;
        }

        public RegistryResult GetRegistryKeyData(string target, string subkey, string subvalue)
        {
            var data = new RegistryResult();
            
            try
            {
                var baseKey = OpenRemoteRegistry(target);
                var value = baseKey.GetValue(subkey, subvalue);
                data.Value = value;

                data.Collected = true;
            }
            catch (IOException e)
            {
                _log.LogError(e, "Error getting data from registry for {Target}: {RegSubKey}:{RegValue}",
                    target, subkey, subvalue);
                data.FailureReason = "Target machine was not found or not connectable";
            }
            catch (SecurityException e)
            {
                _log.LogError(e, "Error getting data from registry for {Target}: {RegSubKey}:{RegValue}",
                    target, subkey, subvalue);
                data.FailureReason = "User does not have the proper permissions to perform this operation";
            }
            catch (UnauthorizedAccessException e)
            {
                _log.LogError(e, "Error getting data from registry for {Target}: {RegSubKey}:{RegValue}",
                    target, subkey, subvalue);
                data.FailureReason = "User does not have the necessary registry rights";
            }
            catch (Exception e)
            {
                _log.LogError(e, "Error getting data from registry for {Target}: {RegSubKey}:{RegValue}",
                    target, subkey, subvalue);
                data.FailureReason = e.Message;
            }

            return data;
        }

        /// <summary>
        /// Get EnrollmentAgentRights registry value from the remote machine for processing security/enrollmentagentrights
        /// </summary>
        /// <param name="target"></param>
        /// <param name="caName"></param>
        /// <returns></returns>
        [ExcludeFromCodeCoverage]
        private RegistryResult GetEnrollmentAgentRights(string target, string caName)
        {
            var regSubKey = $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{caName}";
            var regValue = "EnrollmentAgentRights";

            return GetRegistryKeyData(target, regSubKey, regValue);
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
        public BoolRegistryAPIResult IsUserSpecifiesSanEnabled(string target, string caName)
        {
            var ret = new BoolRegistryAPIResult();
            var subKey =
                $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{caName}\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy";
            const string subValue = "EditFlags";
            var data = GetRegistryKeyData(target, subKey, subValue);

            ret.Collected = data.Collected;
            if (!data.Collected)
            {
                ret.FailureReason = data.FailureReason;
                return ret;
            }

            if (data.Value == null)
            {
                return ret;
            }

            var editFlags = (int)data.Value;
            ret.Value = (editFlags & 0x00040000) == 0x00040000;

            return ret;
        }

        public TypedPrincipal GetRegistryPrincipal(SecurityIdentifier sid, string computerDomain, string computerName, bool isDomainController, string computerObjectId, SecurityIdentifier machineSid)
        {
            _log.LogTrace("Got principal with sid {SID} on computer {ComputerName}", sid.Value, computerName);

            //Check if our sid is filtered
            if (Helpers.IsSidFiltered(sid.Value))
                return null;

            if (isDomainController)
            {
                var result = ResolveDomainControllerPrincipal(sid.Value, computerDomain);
                if (result != null)
                    return result;
            }

            //If we get a local well known principal, we need to convert it using the computer's domain sid
            if (ConvertLocalWellKnownPrincipal(sid, computerObjectId, computerDomain, out var principal))
            {
                _log.LogTrace("Got Well Known Principal {SID} on computer {Computer} with type {Type}", principal.ObjectIdentifier, computerName, principal.ObjectType);
                return principal;
            }

            //If the security identifier starts with the machine sid, we need to resolve it as a local principal
            if (machineSid != null && sid.IsEqualDomainSid(machineSid))
            {
                _log.LogTrace("Got local principal {sid} on computer {Computer}", sid.Value, computerName);
                
                // Set label to be local group. It could be a local user or alias but I'm not sure how we can confirm. Besides, it will not have any effect on the end result
                var objectType = Label.LocalGroup;

                // The local group sid is computer machine sid - group rid.
                var groupRid = sid.Rid();
                var newSid = $"{computerObjectId}-{groupRid}";
                return (new TypedPrincipal
                {
                    ObjectIdentifier = newSid,
                    ObjectType = objectType
                });
            }

            //If we get here, we most likely have a domain principal. Do a lookup
            return _utils.ResolveIDAndType(sid.Value, computerDomain);
        }

        private async Task<SecurityIdentifier> GetMachineSid(string computerName, string computerObjectId, string computerDomain, bool isDomainController)
        {
            SecurityIdentifier machineSid = null;

            //Try to get the machine sid for the computer if its not already cached
            if (!Cache.GetMachineSid(computerObjectId, out var tempMachineSid))
            {
                // Open a handle to the server
                var openServerResult = OpenSamServer(computerName);
                if (openServerResult.IsFailed)
                {
                    _log.LogTrace("OpenServer failed on {ComputerName}: {Error}", computerName, openServerResult.SError);
                    await SendComputerStatus(new CSVComputerStatus
                    {
                        Task = "SamConnect",
                        ComputerName = computerName,
                        Status = openServerResult.SError
                    });
                    return null;
                }

                var server = openServerResult.Value;
                var getMachineSidResult = server.GetMachineSid();
                if (getMachineSidResult.IsFailed)
                {
                    _log.LogTrace("GetMachineSid failed on {ComputerName}: {Error}", computerName, getMachineSidResult.SError);
                    await SendComputerStatus(new CSVComputerStatus
                    {
                        Status = getMachineSidResult.SError,
                        ComputerName = computerName,
                        Task = "GetMachineSid"
                    });
                    //If we can't get a machine sid, we wont be able to make local principals with unique object ids, or differentiate local/domain objects
                    _log.LogWarning("Unable to get machineSid for {Computer}: {Status}", computerName, getMachineSidResult.SError);
                    return null;
                }

                machineSid = getMachineSidResult.Value;
                Cache.AddMachineSid(computerObjectId, machineSid.Value);
            }
            else
            {
                machineSid = new SecurityIdentifier(tempMachineSid);
            }

            return machineSid;
        }

        // TODO: Copied from URA processor. Find a way to have this function in a shared spot
        private TypedPrincipal ResolveDomainControllerPrincipal(string sid, string computerDomain)
        {
            //If the server is a domain controller and we have a well known group, use the domain value
            if (_utils.GetWellKnownPrincipal(sid, computerDomain, out var wellKnown))
                return wellKnown;
            //Otherwise, do a domain lookup
            return _utils.ResolveIDAndType(sid, computerDomain);
        }

        // TODO: Copied from URA processor. Find a way to have this function in a shared spot
        private bool ConvertLocalWellKnownPrincipal(SecurityIdentifier sid, string computerDomainSid,
            string computerDomain, out TypedPrincipal principal)
        {
            if (WellKnownPrincipal.GetWellKnownPrincipal(sid.Value, out var common))
            {
                //The everyone and auth users principals are special and will be converted to the domain equivalent
                if (sid.Value is "S-1-1-0" or "S-1-5-11")
                {
                    _utils.GetWellKnownPrincipal(sid.Value, computerDomain, out principal);
                    return true;
                }

                //Use the computer object id + the RID of the sid we looked up to create our new principal
                principal = new TypedPrincipal
                {
                    ObjectIdentifier = $"{computerDomainSid}-{sid.Rid()}",
                    ObjectType = common.ObjectType switch
                    {
                        Label.User => Label.LocalUser,
                        Label.Group => Label.LocalGroup,
                        _ => common.ObjectType
                    }
                };

                return true;
            }

            principal = null;
            return false;
        }

        public virtual Result<ISAMServer> OpenSamServer(string computerName)
        {
            var result = SAMServer.OpenServer(computerName);
            if (result.IsFailed)
            {
                return Result<ISAMServer>.Fail(result.SError);
            }

            return Result<ISAMServer>.Ok(result.Value);
        }

        private async Task SendComputerStatus(CSVComputerStatus status)
        {
            if (ComputerStatusEvent is not null) await ComputerStatusEvent(status);
        }

    }

    public class EnrollmentAgentRestriction
    {
        public EnrollmentAgentRestriction(QualifiedAce ace, string computerDomain, string certTemplatesLocation, CertAbuseProcessor certAbuseProcessor, string computerName, bool isDomainController, string computerObjectId, SecurityIdentifier machineSid)
        {
            var targets = new List<TypedPrincipal>();
            var index = 0;

            // Access type (Allow/Deny)
            AccessType = ace.AceType.ToString();

            // Agent
            Agent = certAbuseProcessor.GetRegistryPrincipal(ace.SecurityIdentifier, computerDomain, computerName, isDomainController, computerObjectId, machineSid);

            // Targets
            var opaque = ace.GetOpaque();
            var sidCount = BitConverter.ToUInt32(opaque, 0);
            index += 4;
            for (var i = 0; i < sidCount; i++)
            {
                var sid = new SecurityIdentifier(opaque, index);
                targets.Add(certAbuseProcessor.GetRegistryPrincipal(ace.SecurityIdentifier, computerDomain, computerName, isDomainController, computerObjectId, machineSid));
                index += sid.BinaryLength;
            }
            Targets = targets.ToArray();

            // Template
            if (index < opaque.Length)
            {
                AllTemplates = false;
                var template = Encoding.Unicode.GetString(opaque, index, opaque.Length - index - 2).Replace("\u0000", string.Empty);

                // Attempt to resolve the cert template by CN
                Template = certAbuseProcessor._utils.ResolveCertTemplateByProperty(template, LDAPProperties.CanonicalName, certTemplatesLocation, computerDomain);

                // Attempt to resolve the cert template by OID
                if (Template == null)
                {
                    Template = certAbuseProcessor._utils.ResolveCertTemplateByProperty(template, LDAPProperties.CertTemplateOID, certTemplatesLocation, computerDomain);
                }
            }
            else
            {
                AllTemplates = true;
            }
        }

        public string AccessType { get; set; }
        public TypedPrincipal Agent { get; set; }
        public TypedPrincipal[] Targets { get; set; }
        public TypedPrincipal Template { get; set; }
        public bool AllTemplates { get; set; } = false;
    }

    public class CertRegistryResult
    {
        public bool Collected { get; set; } = false;
        public byte[] Value { get; set; }
        public string FailureReason { get; set; }
    }
}