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
        public delegate void ComputerStatusDelegate(CSVComputerStatus status);
        private readonly ILogger _log;
        private readonly ILDAPUtils _utils;

        public UserRightsAssignmentProcessor(ILDAPUtils utils, ILogger log = null)
        {
            _utils = utils;
            _log = log ?? Logging.LogProvider.CreateLogger("UserRightsAssignmentProcessor");
        }

        public event ComputerStatusDelegate ComputerStatusEvent;

        /// <summary>
        ///     Gets principals with the requested privileges on the target computer
        /// </summary>
        /// <param name="computerName"></param>
        /// <param name="computerObjectId">The objectid of the computer in the domain</param>
        /// <param name="computerDomain"></param>
        /// <param name="isDomainController">Is the computer a domain controller</param>
        /// <param name="desiredPrivileges"></param>
        /// <returns></returns>
        public IEnumerable<UserRightsAssignmentAPIResult> GetUserRightsAssignments(string computerName,
            string computerObjectId, string computerDomain, bool isDomainController, string[] desiredPrivileges = null)
        {
            var policyOpenResult = LSAPolicy.OpenPolicy(computerName);
            if (policyOpenResult.IsFailed)
            {
                _log.LogDebug("LSAOpenPolicy failed on {ComputerName} with status {Status}", computerName,
                    policyOpenResult.Status);
                SendComputerStatus(new CSVComputerStatus
                {
                    Task = "LSAOpenPolicy",
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
                    _log.LogDebug(
                        "LSAEnumerateAccountsWithUserRight failed on {ComputerName} with status {Status} for privilege {Privilege}",
                        computerName, policyOpenResult.Status, privilege);
                    SendComputerStatus(new CSVComputerStatus
                    {
                        ComputerName = computerName,
                        Status = enumerateAccountsResult.Status.ToString(),
                        Task = "LSAEnumerateAccountsWithUserRight"
                    });
                    result.FailureReason =
                        $"LSAEnumerateAccountsWithUserRights returned {enumerateAccountsResult.Status}";
                    yield return result;
                    continue;
                }

                SendComputerStatus(new CSVComputerStatus
                {
                    ComputerName = computerName,
                    Status = CSVComputerStatus.StatusSuccess,
                    Task = "LSAEnumerateAccountsWithUserRight"
                });

                if (!Cache.GetMachineSid(computerObjectId, out var machineSid))
                {
                    var getMachineSidResult = server.GetLocalDomainInformation();
                    if (getMachineSidResult.IsFailed)
                    {
                        machineSid = "UNKNOWN";
                    }
                    else
                    {
                        machineSid = getMachineSidResult.Value.Sid;
                        Cache.AddMachineSid(computerObjectId, machineSid);
                    }
                }

                var resolved = new List<TypedPrincipal>();
                var names = new List<NamedPrincipal>();

                foreach (var value in enumerateAccountsResult.Value)
                {
                    var (sid, name, use, domain) = value;
                    if (Helpers.IsSidFiltered(sid.Value))
                        continue;

                    if (isDomainController)
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

                result.Collected = true;
                result.LocalNames = names.ToArray();
                result.Results = resolved.ToArray();
                yield return result;
            }
        }

        private void SendComputerStatus(CSVComputerStatus status)
        {
            ComputerStatusEvent?.Invoke(status);
        }
    }
}