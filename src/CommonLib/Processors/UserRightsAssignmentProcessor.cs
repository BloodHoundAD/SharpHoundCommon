using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundRPC.Shared;
using SharpHoundRPC.Wrappers;

namespace SharpHoundCommonLib.Processors
{
    public class UserRightsAssignmentProcessor
    {
        private readonly ILogger _log;
        private readonly ILDAPUtils _utils;
        private readonly string[] _filteredSids =
        {
            "S-1-5-2", "S-1-5-2", "S-1-5-3", "S-1-5-4", "S-1-5-6", "S-1-5-7", "S-1-2", "S-1-2-0", "S-1-5-18",
            "S-1-5-19", "S-1-5-20"
        };
        
        public delegate void ComputerStatusDelegate(CSVComputerStatus status);
        public event ComputerStatusDelegate ComputerStatusEvent;
        
        public UserRightsAssignmentProcessor(ILDAPUtils utils, ILogger log = null)
        {
            _utils = utils;
            _log = log ?? Logging.LogProvider.CreateLogger("LocalGroupProcessor");
        }

        public IEnumerable<UserRightsAssignmentAPIResult> GetUserRightsAssignments(string computerName, string computerDomainSid, string computerDomain, string[] desiredPrivileges = null)
        {
            var computerSid = new SecurityIdentifier(computerDomainSid);
            var policyOpenResult = LSAPolicy.OpenPolicy(computerName);
            if (policyOpenResult.IsFailed)
            {
                SendComputerStatus(new CSVComputerStatus
                {
                    Task = "SamConnect",
                    ComputerName = computerName,
                    Status = policyOpenResult.Status.ToString()
                });
                yield break;
            }

            var server = policyOpenResult.Value;
            desiredPrivileges ??= LSAPrivileges.DesiredPrivileges;
            foreach (var privilege in desiredPrivileges)
            {
                var result = new UserRightsAssignmentAPIResult
                {
                    Collected = false,
                    Privilege = privilege
                };

                var enumerateAccountsResult = server.GetResolvedPrincipalsWithPrivilege(privilege);
                if (enumerateAccountsResult.IsFailed)
                {
                    SendComputerStatus(new CSVComputerStatus
                    {
                        ComputerName = computerName,
                        Status = enumerateAccountsResult.Status.ToString(),
                        Task = "LSAEnumerateAccountsWithUserRight"
                    });
                    result.FailureReason =
                        $"LSAEnumerateAccountsWithUserRights returned {enumerateAccountsResult.Status}";
                    yield return result;
                }

                if (!Cache.GetMachineSid(computerDomainSid, out var machineSid))
                {
                    var getMachineSidResult = server.GetLocalDomainInformation();
                    if (getMachineSidResult.IsFailed)
                    {
                        machineSid = "UNKNOWN";
                    }
                    else
                    {
                        machineSid = getMachineSidResult.Value.Sid;
                        Cache.AddMachineSid(computerDomainSid, machineSid);
                    }
                }

                var isDc = computerSid.IsEqualDomainSid(new SecurityIdentifier(machineSid));
                
                var resolved = new List<TypedPrincipal>();
                var names = new List<NamedPrincipal>();

                foreach (var value in enumerateAccountsResult.Value)
                {
                    var (sid, name, use, domain) = value;
                    if (IsSidFiltered(sid))
                        continue;

                    if (isDc)
                    {
                        if (_utils.GetWellKnownPrincipal(sid.Value, computerDomain, out var principal))
                        {
                            resolved.Add(principal);
                        }
                        else
                        {
                            var res = _utils.ResolveIDAndType(sid.Value, computerDomain);
                            resolved.Add(res);
                        }
                    }
                    else
                    {
                        if (WellKnownPrincipal.GetWellKnownPrincipal(sid.Value, out var common))
                        {
                            if (machineSid == "UNKNOWN")
                                continue;
                            var convertedId = $"{machineSid}-{sid.Rid()}";
                            names.Add(new NamedPrincipal
                            {
                                ObjectId = convertedId,
                                PrincipalName = common.ObjectIdentifier
                            });
                            
                            var objectType = common.ObjectType switch
                            {
                                Label.User => Label.LocalUser,
                                Label.Group => Label.LocalGroup,
                                _ => common.ObjectType
                            };
                            resolved.Add(new TypedPrincipal
                            {
                                ObjectIdentifier = convertedId,
                                ObjectType = objectType
                            });
                        }
                        else
                        {
                            var objectType = use switch
                            {
                                SharedEnums.SidNameUse.User => Label.LocalUser,
                                SharedEnums.SidNameUse.Group => Label.LocalGroup,
                                SharedEnums.SidNameUse.Alias => Label.LocalGroup,
                                _ => Label.Base
                            };
                            
                            names.Add(new NamedPrincipal
                            {
                                ObjectId = sid.ToString(),
                                PrincipalName = name
                            });
                            
                            resolved.Add(new TypedPrincipal
                            {
                                ObjectIdentifier = sid.ToString(),
                                ObjectType = objectType
                            });
                        }
                    }
                }

                result.LocalNames = names.ToArray();
                result.Results = resolved.ToArray();
                yield return result;
            }
        }
        
        private bool IsSidFiltered(SecurityIdentifier identifier)
        {
            var value = identifier.Value;

            if (value.StartsWith("S-1-5-80") || value.StartsWith("S-1-5-82") ||
                value.StartsWith("S-1-5-90") || value.StartsWith("S-1-5-96"))
                return true;

            if (_filteredSids.Contains(value))
                return true;

            return false;
        }
        
        private void SendComputerStatus(CSVComputerStatus status)
        {
            ComputerStatusEvent?.Invoke(status);
        }
    }
}