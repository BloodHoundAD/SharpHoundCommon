using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib;
using SharpHoundCommonLib.DirectoryObjects;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.Processors;

namespace SharpHoundProcessors {
    public class BaseObjectProcessor {
        private readonly ACLProcessor _aclProcessor;
        private readonly CertAbuseProcessor _certAbuseProcessor;
        private readonly ComputerAvailability _computerAvailability;
        private readonly ComputerSessionProcessor _computerSessionProcessor;
        private readonly ContainerProcessor _containerProcessor;
        private readonly DomainTrustProcessor _domainTrustProcessor;
        private readonly GroupProcessor _groupProcessor;
        private readonly LdapPropertyProcessor _ldapPropertyProcessor;
        private readonly LocalGroupProcessor _localGroupProcessor;
        private readonly DCRegistryProcessor _dcRegistryProcessor;
        private readonly SPNProcessors _spnProcessor;
        private readonly UserRightsAssignmentProcessor _userRightsAssignmentProcessor;
        private readonly GPOLocalGroupProcessor _gpoLocalGroupProcessor;
        private readonly ProcessorConfig _processorConfig;

        private readonly ILogger _log;
        private readonly ILdapUtils _utils;
        private readonly CollectionMethod _collectionMethod;

        public BaseObjectProcessor(ProcessorConfig config, ILdapUtils utils, ILogger log,
            CollectionMethod collectionMethods, NativeMethods nativeMethods = null, PortScanner scanner = null) {
            _processorConfig = config;
            _collectionMethod = collectionMethods;
            _utils = utils;
            _aclProcessor = new ACLProcessor(utils);
            _certAbuseProcessor = new CertAbuseProcessor(utils);
            nativeMethods ??= new NativeMethods();
            scanner ??= new PortScanner();
            _computerAvailability = new ComputerAvailability(scanner, config.PortScanTimeout, config.ComputerExpiryDays,
                config.SkipPortScan, config.SkipComputerAgeCheck);
            _computerSessionProcessor = new ComputerSessionProcessor(utils,
                nativeMethods, currentUserName: config.OverrideCurrentUserName,
                doLocalAdminSessionEnum: config.UseAlternateLocalAdminCredentials,
                localAdminUsername: config.AlternateLocalAdminUsername,
                localAdminPassword: config.AlternateLocalAdminPassword);
            _containerProcessor = new ContainerProcessor(utils);
            _domainTrustProcessor = new DomainTrustProcessor(utils);
            _groupProcessor = new GroupProcessor(utils);
            _ldapPropertyProcessor = new LdapPropertyProcessor(utils);
            _localGroupProcessor = new LocalGroupProcessor(utils);
            _dcRegistryProcessor = new DCRegistryProcessor(utils);
            _spnProcessor = new SPNProcessors(utils);
            _userRightsAssignmentProcessor = new UserRightsAssignmentProcessor(utils);
            _gpoLocalGroupProcessor = new GPOLocalGroupProcessor(utils);
            _log = log;
        }

        public async Task<OutputBase> ProcessDirectoryObject(IDirectoryObject directoryObject) {
            var (success, resolvedSearchResult) = await LdapUtils.ResolveSearchResult(directoryObject, _utils);
            directoryObject.TryGetDistinguishedName(out var distinguishedName);

            if (!IsDistinguishedNameValid(distinguishedName)) {
                return default;
            }

            if (!success || resolvedSearchResult.ObjectType == Label.Base) {
                if (!string.IsNullOrWhiteSpace(distinguishedName)) {
                    _log.LogTrace("Consumer failed to resolve entry for {item}", distinguishedName);
                }

                return default;
            }

            switch (resolvedSearchResult.ObjectType) {
                case Label.User:
                    return await ProcessUserObject(directoryObject, resolvedSearchResult);
                case Label.Computer:
                    return await ProcessComputerObject(directoryObject, resolvedSearchResult);
                case Label.Group:
                    return await ProcessGroupObject(directoryObject, resolvedSearchResult);
                case Label.GPO:
                    return await ProcessGPOObject(directoryObject, resolvedSearchResult);
                case Label.Domain:
                    return await ProcessDomainObject(directoryObject, resolvedSearchResult);
                case Label.OU:
                    break;
                case Label.Container:
                    break;
                case Label.Configuration:
                    break;
                case Label.CertTemplate:
                    break;
                case Label.RootCA:
                    break;
                case Label.AIACA:
                    break;
                case Label.EnterpriseCA:
                    break;
                case Label.NTAuthStore:
                    break;
                case Label.IssuancePolicy:
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }
        }

        private async Task<User> ProcessUserObject(IDirectoryObject directoryObject, ResolvedSearchResult resolvedSearchResult) {
            var output = new User {
                ObjectIdentifier = resolvedSearchResult.ObjectId
            };
            output.Properties.Add(OutputNames.MSA, directoryObject.IsMSA());
            output.Properties.Add(OutputNames.GMSA, directoryObject.IsGMSA());
            await CollectObjectProperties(directoryObject, resolvedSearchResult, output);
            await CollectAclData(directoryObject, resolvedSearchResult, output);
            await CollectGroupData(directoryObject, resolvedSearchResult, output);
            await CollectContainerData(directoryObject, resolvedSearchResult, output);
                    
            if (_collectionMethod.HasFlag(CollectionMethod.SPNTargets)) {
                output.SPNTargets = await _spnProcessor.ReadSPNTargets(resolvedSearchResult, directoryObject)
                    .ToArrayAsync();
            }

            return output;
        }
        
        private async Task<Computer> ProcessComputerObject(IDirectoryObject directoryObject,
            ResolvedSearchResult resolvedSearchResult) {
            var output = new Computer {
                ObjectIdentifier = resolvedSearchResult.ObjectId
            };
            output.Properties.Add(OutputNames.HasLAPS, directoryObject.HasLAPS());
            output.IsDC = resolvedSearchResult.IsDomainController;
            output.DomainSID = resolvedSearchResult.DomainSid;

            await CollectObjectProperties(directoryObject, resolvedSearchResult, output);
            await CollectAclData(directoryObject, resolvedSearchResult, output);
            await CollectGroupData(directoryObject, resolvedSearchResult, output);
            await CollectContainerData(directoryObject, resolvedSearchResult, output);

            if (!_collectionMethod.IsComputerCollectionSet()) {
                return output;
            }

            var apiName = _processorConfig.DNSName != null
                ? directoryObject.GetDNSName(_processorConfig.DNSName) ?? resolvedSearchResult.DisplayName
                : resolvedSearchResult.DisplayName;

            var availabilityResult = await _computerAvailability.IsComputerAvailable(apiName, directoryObject);
            output.Status = availabilityResult;

            if (!availabilityResult.Connectable) {
                return output;
            }

            if (resolvedSearchResult.IsDomainController && _collectionMethod.HasFlag(CollectionMethod.DCRegistry)) {
                await _processorConfig.Delay();
                output.DCRegistryData = new DCRegistryData {
                    CertificateMappingMethods = _dcRegistryProcessor.GetCertificateMappingMethods(apiName),
                    StrongCertificateBindingEnforcement =
                        _dcRegistryProcessor.GetStrongCertificateBindingEnforcement(apiName)
                };
            }

            if (_collectionMethod.HasFlag(CollectionMethod.Session)) {
                await _processorConfig.Delay();
                output.Sessions = await _computerSessionProcessor.ReadUserSessions(apiName, resolvedSearchResult.ObjectId, resolvedSearchResult.DomainSid);
            }

            if (_collectionMethod.HasFlag(CollectionMethod.LoggedOn)) {
                await _processorConfig.Delay();
                output.PrivilegedSessions =
                    await _computerSessionProcessor.ReadUserSessionsPrivileged(apiName, directoryObject,
                        resolvedSearchResult);

                if (!_processorConfig.SkipRegistryLoggedOn) {
                    await _processorConfig.Delay();
                    output.RegistrySessions = await _computerSessionProcessor.ReadUserSessionsRegistry(apiName,
                        resolvedSearchResult.Domain, resolvedSearchResult.ObjectId);
                }
            }

            if (_collectionMethod.HasFlag(CollectionMethod.UserRights)) {
                await _processorConfig.Delay();
                output.UserRights = await _userRightsAssignmentProcessor.GetUserRightsAssignments(apiName,
                    resolvedSearchResult.ObjectId, resolvedSearchResult.Domain,
                    resolvedSearchResult.IsDomainController).ToArrayAsync();
            }

            if (!_collectionMethod.IsLocalGroupCollectionSet()) {
                return output;
            }

            await _processorConfig.Delay();
            output.LocalGroups = await _localGroupProcessor.GetLocalGroups(apiName, resolvedSearchResult.ObjectId,
                resolvedSearchResult.Domain, resolvedSearchResult.IsDomainController).ToArrayAsync();

            return output;
        }

        public async Task<Group> ProcessGroupObject(IDirectoryObject entry, ResolvedSearchResult resolvedSearchResult) {
            var output = new Group {
                ObjectIdentifier = resolvedSearchResult.ObjectId
            };

            await CollectObjectProperties(entry, resolvedSearchResult, output);
            await CollectAclData(entry, resolvedSearchResult, output);
            await CollectGroupData(entry, resolvedSearchResult, output);
            await CollectContainerData(entry, resolvedSearchResult, output);

            return output;
        }

        public async Task<GPO> ProcessGPOObject(IDirectoryObject entry, ResolvedSearchResult resolvedSearchResult) {
            var output = new GPO {
                ObjectIdentifier = resolvedSearchResult.ObjectId
            };

            await CollectObjectProperties(entry, resolvedSearchResult, output);
            await CollectAclData(entry, resolvedSearchResult, output);

            return output;
        }

        public async Task<Domain>
            ProcessDomainObject(IDirectoryObject entry, ResolvedSearchResult resolvedSearchResult) {
            var output = new Domain {
                ObjectIdentifier = resolvedSearchResult.ObjectId
            };

            if (await _utils.GetForest(resolvedSearchResult.DisplayName) is (true, var forest) &&
                await _utils.GetDomainSidFromDomainName(forest) is (true, var forestSid)) {
                output.ForestRootIdentifier = forestSid;
            }

            await CollectObjectProperties(entry, resolvedSearchResult, output);
            await CollectAclData(entry, resolvedSearchResult, output);
            await CollectContainerData(entry, resolvedSearchResult, output);

            if (_collectionMethod.HasFlag(CollectionMethod.Trusts)) {
                output.Trusts = await _domainTrustProcessor.EnumerateDomainTrusts(resolvedSearchResult.DisplayName).ToArrayAsync();
            }

            if (_collectionMethod.HasFlag(CollectionMethod.GPOLocalGroup)) {
                output.GPOChanges = await _gpoLocalGroupProcessor.ReadGPOLocalGroups(entry);
            }

            return output;
        }

        private async Task CollectContainerData(IDirectoryObject entry, ResolvedSearchResult resolvedSearchResult,
            OutputBase output) {
            if (!_collectionMethod.HasFlag(CollectionMethod.Container)) {
                return;
            }

            if (resolvedSearchResult.ObjectType != Label.Domain && entry.TryGetDistinguishedName(out var dn) &&
                await _containerProcessor.GetContainingObject(dn) is (true, var container)) {
                output.ContainedBy = container;
            }

            switch (output) {
                case Domain d:
                    d.Links = await _containerProcessor.ReadContainerGPLinks(resolvedSearchResult, entry).ToArrayAsync();
                    break;
                case OU o:
                    o.Links = await _containerProcessor.ReadContainerGPLinks(resolvedSearchResult, entry).ToArrayAsync();
                    break;
            }
        }

        private async Task CollectAclData(IDirectoryObject entry, ResolvedSearchResult resolvedSearchResult,
            OutputBase output) {
            if (!_collectionMethod.HasFlag(CollectionMethod.ACL)) {
                return;
            }

            var aces = await _aclProcessor.ProcessACL(resolvedSearchResult, entry).ToArrayAsync();
            if (resolvedSearchResult.ObjectType == Label.User) {
                var gmsaAces = await _aclProcessor.ProcessGMSAReaders(resolvedSearchResult, entry).ToArrayAsync();
                aces = aces.Concat(gmsaAces).ToArray();
            }

            output.Aces = aces;
            output.IsACLProtected = _aclProcessor.IsACLProtected(entry);
            output.Properties.Add(OutputNames.IsACLProtected, output.IsACLProtected);

            switch (output) {
                case Container c:
                    c.InheritanceHashes = _aclProcessor.GetInheritedAceHashes(entry, resolvedSearchResult).ToArray();
                    break;
                case Domain d:
                    d.InheritanceHashes = _aclProcessor.GetInheritedAceHashes(entry, resolvedSearchResult).ToArray();
                    break;
                case OU o:
                    o.InheritanceHashes = _aclProcessor.GetInheritedAceHashes(entry, resolvedSearchResult).ToArray();
                    break;
            }
        }

        private async Task CollectObjectProperties(IDirectoryObject entry, ResolvedSearchResult resolvedSearchResult,
            OutputBase output) {
            //Always process common properties
            var commonProperties = CollectCommonProperties(entry, resolvedSearchResult);
            commonProperties.ToList().ForEach(x => output.Properties[x.Key] = x.Value);

            //Quick exit if the collection method isn't set
            if (!_collectionMethod.HasFlag(CollectionMethod.ObjectProps)) {
                return;
            }
            
            if (output is User u) {
                var userProperties = await _ldapPropertyProcessor.ReadUserProperties(entry, resolvedSearchResult);
                userProperties.Props.ToList().ForEach(x => output.Properties[x.Key] = x.Value);
                u.AllowedToDelegate = userProperties.AllowedToDelegate;
                u.HasSIDHistory = userProperties.SidHistory;
            } else if (output is Computer c) {
                var computerProperties =
                    await _ldapPropertyProcessor.ReadComputerProperties(entry, resolvedSearchResult);
                computerProperties.Props.ToList().ForEach(x => output.Properties[x.Key] = x.Value);
                c.AllowedToAct = computerProperties.AllowedToAct;
                c.AllowedToDelegate = computerProperties.AllowedToDelegate;
                c.HasSIDHistory = computerProperties.SidHistory;
                c.DumpSMSAPassword = computerProperties.DumpSMSAPassword;
            } else {
                switch (resolvedSearchResult.ObjectType) {
                    case Label.Group:
                        LdapPropertyProcessor.ReadGroupProperties(entry).ToList()
                            .ForEach(x => output.Properties[x.Key] = x.Value);
                        break;
                    case Label.GPO:
                        LdapPropertyProcessor.ReadGPOProperties(entry).ToList()
                            .ForEach(x => output.Properties[x.Key] = x.Value);
                        break;
                    case Label.OU:
                        LdapPropertyProcessor.ReadOUProperties(entry).ToList()
                            .ForEach(x => output.Properties[x.Key] = x.Value);
                        break;
                    case Label.Container:
                    case Label.Configuration:
                        LdapPropertyProcessor.ReadContainerProperties(entry).ToList()
                            .ForEach(x => output.Properties[x.Key] = x.Value);
                        break;
                    case Label.CertTemplate:
                        LdapPropertyProcessor.ReadCertTemplateProperties(entry).ToList()
                            .ForEach(x => output.Properties[x.Key] = x.Value);
                        break;
                    case Label.RootCA:
                        LdapPropertyProcessor.ReadRootCAProperties(entry).ToList()
                            .ForEach(x => output.Properties[x.Key] = x.Value);
                        break;
                    case Label.AIACA:
                        LdapPropertyProcessor.ReadAIACAProperties(entry).ToList()
                            .ForEach(x => output.Properties[x.Key] = x.Value);
                        break;
                    case Label.EnterpriseCA:
                        LdapPropertyProcessor.ReadEnterpriseCAProperties(entry).ToList()
                            .ForEach(x => output.Properties[x.Key] = x.Value);
                        break;
                    case Label.NTAuthStore:
                        LdapPropertyProcessor.ReadNTAuthStoreProperties(entry).ToList()
                            .ForEach(x => output.Properties[x.Key] = x.Value);
                        break;
                    case Label.Domain:
                        var domainProperties = await _ldapPropertyProcessor.ReadDomainProperties(entry, resolvedSearchResult.Domain);
                        domainProperties.ToList().ForEach(x => output.Properties[x.Key] = x.Value);
                        break;
                }
            }

            if (_processorConfig.CollectAllProperties) {
                _ldapPropertyProcessor.ParseAllProperties(entry).ToList().ForEach(x => {
                    if (!output.Properties.ContainsKey(x.Key)) {
                        output.Properties[x.Key] = x.Value;
                    }
                });
            }
        }

        private async Task CollectGroupData(IDirectoryObject entry, ResolvedSearchResult resolvedSearchResult,
            OutputBase output) {
            if (!_collectionMethod.HasFlag(CollectionMethod.Group)) {
                return;
            }

            if (output is User u) {
                var primaryGroupId = entry.GetProperty(LDAPProperties.PrimaryGroupID);
                u.PrimaryGroupSID =
                    GroupProcessor.GetPrimaryGroupInfo(primaryGroupId, resolvedSearchResult.ObjectId);
            } else if (output is Computer c) {
                var primaryGroupId = entry.GetProperty(LDAPProperties.PrimaryGroupID);
                c.PrimaryGroupSID =
                    GroupProcessor.GetPrimaryGroupInfo(primaryGroupId, resolvedSearchResult.ObjectId);
            } else if (output is Group g) {
                g.Members = await _groupProcessor.ReadGroupMembers(resolvedSearchResult, entry).ToArrayAsync();
            }
        }

        private static Dictionary<string, object> CollectCommonProperties(IDirectoryObject entry,
            ResolvedSearchResult resolvedSearchResult) {
            var props = new Dictionary<string, object> {
                { OutputNames.Domain, resolvedSearchResult.Domain },
                { OutputNames.Name, resolvedSearchResult.DisplayName },
            };

            if (entry.TryGetDistinguishedName(out var distinguishedName)) {
                props.Add(OutputNames.DistinguishedName, distinguishedName.ToUpper());
            }

            if (!string.IsNullOrWhiteSpace(resolvedSearchResult.DomainSid)) {
                props.Add(OutputNames.DomainSID, resolvedSearchResult.DomainSid);
            }

            if (entry.TryGetProperty(LDAPProperties.SAMAccountName, out var samAccountName)) {
                props.Add(OutputNames.SAMAccountName, samAccountName);
            }

            return props;
        }

        private static bool IsDistinguishedNameValid(string name) {
            var n = name.ToLower();

            //Filter out domainupdates objects
            if (n.Contains("cn=domainupdates,cn=system")) {
                return false;
            }

            if (n.Contains("cn=policies,cn=system") && (n.StartsWith("cn=user") || n.StartsWith("cn=machine"))) {
                return false;
            }

            return true;
        }
    }
}