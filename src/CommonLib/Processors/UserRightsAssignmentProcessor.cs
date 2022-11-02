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

            SecurityIdentifier machineSid;
            if (!Cache.GetMachineSid(computerObjectId, out var temp))
            {
                var getMachineSidResult = server.GetLocalDomainInformation();
                if (getMachineSidResult.IsFailed)
                {
                    _log.LogWarning("Failed to get machine sid for {Server}: {Status}. Abandoning URA collection", computerName, getMachineSidResult.Status);
                    SendComputerStatus(new CSVComputerStatus
                    {
                        ComputerName = computerName,
                        Status = getMachineSidResult.Status.ToString(),
                        Task = "LSAGetMachineSID"
                    });
                    yield break;
                }

                machineSid = new SecurityIdentifier(getMachineSidResult.Value.Sid);
                Cache.AddMachineSid(computerObjectId, getMachineSidResult.Value.Sid);
            }
            else
            {
                machineSid = new SecurityIdentifier(temp);
            }
            
            foreach (var privilege in desiredPrivileges)
            {
                var ret = new UserRightsAssignmentAPIResult
                {
                    Collected = false,
                    Privilege = privilege
                };

                //Ask for all principals with the specified privilege. 
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
                    ret.FailureReason =
                        $"LSAEnumerateAccountsWithUserRights returned {enumerateAccountsResult.Status}";
                    yield return ret;
                    continue;
                }

                SendComputerStatus(new CSVComputerStatus
                {
                    ComputerName = computerName,
                    Status = CSVComputerStatus.StatusSuccess,
                    Task = "LSAEnumerateAccountsWithUserRight"
                });

                var resolved = new List<TypedPrincipal>();
                var names = new List<NamedPrincipal>();

                foreach (var value in enumerateAccountsResult.Value)
                {
                    var (sid, name, use, _) = value;
                    //Check if our sid is filtered
                    if (Helpers.IsSidFiltered(sid.Value))
                        continue;
                    
                    if (isDomainController)
                    {
                        var result = ResolveDomainControllerPrincipal(sid.Value, computerDomain);
                        if (result != null)
                            resolved.Add(result);
                        continue;
                    }
                    
                    //If we get a local well known principal, we need to convert it using the machine sid
                    if (ConvertLocalWellKnownPrincipal(sid, machineSid.Value, computerDomain, out var principal))
                    {
                        //If the principal is null, it means we hit a weird edge case, but this is a local well known principal 
                        if (principal != null)
                            resolved.Add(principal);
                        continue;
                    }

                    //If the security identifier starts with the machine sid, we need to resolve it as a local account
                    if (sid.IsEqualDomainSid(machineSid))
                    {
                        var objectType = use switch
                        {
                            SharedEnums.SidNameUse.User => Label.LocalUser,
                            SharedEnums.SidNameUse.Group => Label.LocalGroup,
                            SharedEnums.SidNameUse.Alias => Label.LocalGroup,
                            _ => Label.Base
                        };
                        
                        //Throw out local user accounts
                        if (objectType == Label.LocalUser)
                            continue;

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
                        continue;
                    }
                    
                    //If we get here, we most likely have a domain principal in a local group. Do a lookup
                    var resolvedPrincipal = _utils.ResolveIDAndType(sid.Value, computerDomain);
                    if (resolvedPrincipal != null) resolved.Add(resolvedPrincipal);
                }

                ret.Collected = true;
                ret.LocalNames = names.ToArray();
                ret.Results = resolved.ToArray();
                yield return ret;
            }
        }
        
        private TypedPrincipal ResolveDomainControllerPrincipal(string sid, string computerDomain)
        {
            //If the server is a domain controller and we have a well known group, use the domain value
            if (_utils.GetWellKnownPrincipal(sid, computerDomain, out var wellKnown))
                return wellKnown;
            //Otherwise, do a domain lookup
            return _utils.ResolveIDAndType(sid, computerDomain);
        }
        
        private bool ConvertLocalWellKnownPrincipal(SecurityIdentifier sid, string machineSid, string computerDomain, out TypedPrincipal principal)
        {
            if (WellKnownPrincipal.GetWellKnownPrincipal(sid.Value, out var common))
            {
                //The everyone and auth users principals are special and will be converted to the domain equivalent
                if (sid.Value is "S-1-1-0" or "S-1-5-11")
                {
                    _utils.GetWellKnownPrincipal(sid.Value, computerDomain, out principal);
                    return true;
                }

                if (machineSid == "UNKNOWN")
                {
                    principal = null;
                    return true;
                }

                //Use the machinesid + the RID of the sid we looked up to create our new principal
                principal = new TypedPrincipal
                {
                    ObjectIdentifier = $"{machineSid}-{sid.Rid()}",
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

        private void SendComputerStatus(CSVComputerStatus status)
        {
            ComputerStatusEvent?.Invoke(status);
        }
    }
}