using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib;
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
        
        private readonly ILogger _log;
        private readonly ILdapUtils _utils;
        private readonly CollectionMethod _collectionMethod;
        
        public BaseObjectProcessor(ProcessorConfig config, ILdapUtils utils, ILogger log, CollectionMethod collectionMethods, NativeMethods nativeMethods = null, PortScanner scanner = null) {
            _collectionMethod = collectionMethods;
            _utils = utils;
            _aclProcessor = new ACLProcessor(utils);
            _certAbuseProcessor = new CertAbuseProcessor(utils);
            nativeMethods ??= new NativeMethods();
            scanner ??= new PortScanner();
            _computerAvailability = new ComputerAvailability(scanner, config.PortScanTimeout, config.ComputerExpiryDays,
                config.SkipPortScan, config.SkipComputerAgeCheck);
            _computerSessionProcessor = new ComputerSessionProcessor(utils,
                nativeMethods, currentUserName: config.OverrideCurrentUserName, doLocalAdminSessionEnum:config.UseAlternateLocalAdminCredentials,
                localAdminUsername:config.AlternateLocalAdminUsername, localAdminPassword:config.AlternateLocalAdminPassword);
            _containerProcessor = new ContainerProcessor(utils);
            _domainTrustProcessor = new DomainTrustProcessor(utils);
            _groupProcessor = new GroupProcessor(utils);
            _ldapPropertyProcessor = new LdapPropertyProcessor(utils);
            _localGroupProcessor = new LocalGroupProcessor(utils);
            _dcRegistryProcessor = new DCRegistryProcessor(utils);
            _spnProcessor = new SPNProcessors(utils);
            _userRightsAssignmentProcessor = new UserRightsAssignmentProcessor(utils);
            _log = log;
        }

        public async Task<OutputBase> ProcessDirectoryObject(IDirectoryObject directoryObject) {
            var (success, resolvedResult) = await LdapUtils.ResolveSearchResult(directoryObject, _utils);
            directoryObject.TryGetDistinguishedName(out var distinguishedName);
            
            if (!IsDistinguishedNameValid(distinguishedName)) {
                return default;
            }
            
            if (!success || resolvedResult.ObjectType == Label.Base) {
                if (!string.IsNullOrWhiteSpace(distinguishedName)) {
                    _log.LogTrace("Consumer failed to resolve entry for {item}", distinguishedName);
                }

                return default;
            }

            switch (resolvedResult.ObjectType) {
                case Label.Base:
                    break;
                case Label.User:
                    break;
                case Label.Computer:
                    break;
                case Label.Group:
                    break;
                case Label.LocalGroup:
                    break;
                case Label.LocalUser:
                    break;
                case Label.GPO:
                    break;
                case Label.Domain:
                    break;
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
        
        private static Dictionary<string, object> GetCommonProperties(IDirectoryObject entry,
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