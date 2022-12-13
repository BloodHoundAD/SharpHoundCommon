using System;
using System.Collections.Concurrent;
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
    public class LocalGroupProcessor
    {
        public delegate void ComputerStatusDelegate(CSVComputerStatus status);
        private readonly ILogger _log;
        private readonly ILDAPUtils _utils;

        public LocalGroupProcessor(ILDAPUtils utils, ILogger log = null)
        {
            _utils = utils;
            _log = log ?? Logging.LogProvider.CreateLogger("LocalGroupProcessor");
        }

        public event ComputerStatusDelegate ComputerStatusEvent;

        /// <summary>
        ///     Gets local groups from a computer
        /// </summary>
        /// <param name="computerName"></param>
        /// <param name="computerObjectId">The objectsid of the computer in the domain</param>
        /// <param name="computerDomain">The domain the computer belongs too</param>
        /// <param name="isDomainController">Is the computer a domain controller</param>
        /// <returns></returns>
        public IEnumerable<LocalGroupAPIResult> GetLocalGroups(string computerName, string computerObjectId,
            string computerDomain, bool isDomainController)
        {
            //Open a handle to the server
            var openServerResult = SAMServer.OpenServer(computerName);
            if (openServerResult.IsFailed)
            {
                SendComputerStatus(new CSVComputerStatus
                {
                    Task = "SamConnect",
                    ComputerName = computerName,
                    Status = openServerResult.SError
                });
                yield break;
            }

            var server = openServerResult.Value;
            var typeCache = new ConcurrentDictionary<string, CachedLocalItem>();

            //Try to get the machine sid for the computer if its not already cached
            SecurityIdentifier machineSid;
            if (!Cache.GetMachineSid(computerObjectId, out var tempMachineSid))
            {
                var getMachineSidResult = server.GetMachineSid();
                if (getMachineSidResult.IsFailed)
                {
                    SendComputerStatus(new CSVComputerStatus
                    {
                        Status = getMachineSidResult.SError,
                        ComputerName = computerName,
                        Task = "GetMachineSid"
                    });
                    //If we can't get a machine sid, we wont be able to make local principals with unique object ids, or differentiate local/domain objects
                    _log.LogWarning("Unable to get machineSid for {Computer}: {Status}. Abandoning local group processing", computerName, getMachineSidResult.SError);
                    yield break;
                }

                machineSid = getMachineSidResult.Value;
                Cache.AddMachineSid(computerObjectId, machineSid.Value);
            }
            else
            {
                machineSid = new SecurityIdentifier(tempMachineSid);
            }

            //Get all available domains in the server
            var getDomainsResult = server.GetDomains();
            if (getDomainsResult.IsFailed)
            {
                SendComputerStatus(new CSVComputerStatus
                {
                    Task = "GetDomains",
                    ComputerName = computerName,
                    Status = getDomainsResult.SError
                });
                yield break;
            }

            //Loop over each domain result and process its member groups
            foreach (var domainResult in getDomainsResult.Value)
            {
                //Skip non-builtin domains on domain controllers
                if (isDomainController && !domainResult.Name.Equals("builtin", StringComparison.OrdinalIgnoreCase))
                    continue;
                //Open a handle to the domain
                var openDomainResult = server.OpenDomain(domainResult.Name);
                if (openDomainResult.IsFailed)
                {
                    SendComputerStatus(new CSVComputerStatus
                    {
                        Task = $"OpenDomain - {domainResult.Name}",
                        ComputerName = computerName,
                        Status = openDomainResult.SError
                    });
                    continue;
                }

                var domain = openDomainResult.Value;

                //Open a handle to the available aliases
                var getAliasesResult = domain.GetAliases();

                if (getAliasesResult.IsFailed)
                {
                    SendComputerStatus(new CSVComputerStatus
                    {
                        Task = $"GetAliases - {domainResult.Name}",
                        ComputerName = computerName,
                        Status = getAliasesResult.SError
                    });
                    continue;
                }

                foreach (var alias in getAliasesResult.Value)
                {
                    //Try and resolve the group name using several different criteria
                    var resolvedName = ResolveGroupName(alias.Name, computerName, machineSid, computerDomain, alias.Rid,
                        isDomainController,
                        domainResult.Name.Equals("builtin", StringComparison.OrdinalIgnoreCase));
                    var ret = new LocalGroupAPIResult
                    {
                        Name = resolvedName.PrincipalName,
                        ObjectIdentifier = resolvedName.ObjectId
                    };

                    //Open a handle to the alias
                    var openAliasResult = domain.OpenAlias(alias.Rid);
                    if (openAliasResult.IsFailed)
                    {
                        SendComputerStatus(new CSVComputerStatus
                        {
                            Task = $"OpenAlias - {alias.Name}",
                            ComputerName = computerName,
                            Status = openAliasResult.SError
                        });
                        ret.Collected = false;
                        ret.FailureReason = $"SamOpenAliasInDomain failed with status {openAliasResult.SError}";
                        yield return ret;
                        continue;
                    }
                    
                    var localGroup = openAliasResult.Value;
                    //Call GetMembersInAlias to get raw group members
                    var getMembersResult = localGroup.GetMembers();
                    if (getMembersResult.IsFailed)
                    {
                        SendComputerStatus(new CSVComputerStatus
                        {
                            Task = $"GetMembersInAlias - {alias.Name}",
                            ComputerName = computerName,
                            Status = getMembersResult.SError
                        });
                        ret.Collected = false;
                        ret.FailureReason = $"SamGetMembersInAlias failed with status {getMembersResult.SError}";
                        yield return ret;
                        continue;
                    }

                    SendComputerStatus(new CSVComputerStatus
                    {
                        Task = $"GetMembersInAlias - {alias.Name}",
                        ComputerName = computerName,
                        Status = CSVComputerStatus.StatusSuccess
                    });
                    
                    var results = new List<TypedPrincipal>();
                    var names = new List<NamedPrincipal>();

                    foreach (var securityIdentifier in getMembersResult.Value)
                    {
                        //Check if the sid is one of our filtered ones. Throw it out if it is
                        if (Helpers.IsSidFiltered(securityIdentifier.Value))
                            continue;

                        var sidValue = securityIdentifier.Value;

                        if (isDomainController)
                        {
                            var result = ResolveDomainControllerPrincipal(sidValue, computerDomain);
                            if (result != null) results.Add(result);
                            continue;
                        }
                        
                        //If we get a local well known principal, we need to convert it using the machine sid
                        if (ConvertLocalWellKnownPrincipal(securityIdentifier, machineSid.Value, computerDomain, out var principal))
                        {
                            //If the principal is null, it means we hit a weird edge case, but this is a local well known principal 
                            if (principal != null)
                                results.Add(principal);
                            continue;
                        }

                        //If the security identifier starts with the machine sid, we need to resolve it as a local object
                        if (securityIdentifier.IsEqualDomainSid(machineSid))
                        {
                            //Check if we've already previously resolved and cached this sid
                            if (typeCache.TryGetValue(sidValue, out var cachedLocalItem))
                            {
                                results.Add(new TypedPrincipal
                                {
                                    ObjectIdentifier = sidValue,
                                    ObjectType = cachedLocalItem.Type
                                });

                                names.Add(new NamedPrincipal
                                {
                                    ObjectId = sidValue,
                                    PrincipalName = cachedLocalItem.Name
                                });
                                //Move on
                                continue;
                            }
                            
                            //Attempt to lookup the principal in the server directly
                            var lookupUserResult = server.LookupPrincipalBySid(securityIdentifier);
                            if (lookupUserResult.IsFailed)
                            {
                                _log.LogTrace("Unable to resolve local sid {SID}: {Error}", sidValue, lookupUserResult.SError);
                                continue;
                            }

                            var (name, use) = lookupUserResult.Value;
                            var objectType = use switch
                            {
                                SharedEnums.SidNameUse.User => Label.LocalUser,
                                SharedEnums.SidNameUse.Group => Label.LocalGroup,
                                SharedEnums.SidNameUse.Alias => Label.LocalGroup,
                                _ => Label.Base
                            };

                            // Cache whatever we looked up for future lookups
                            typeCache.TryAdd(sidValue, new CachedLocalItem(name, objectType));
                            
                            // Throw out local users
                            if (objectType == Label.LocalUser)
                                continue;
                            
                            results.Add(new TypedPrincipal
                            {
                                ObjectIdentifier = sidValue,
                                ObjectType = objectType
                            });

                            names.Add(new NamedPrincipal
                            {
                                PrincipalName = name,
                                ObjectId = sidValue
                            });
                            continue;
                        }
                        
                        //If we get here, we most likely have a domain principal in a local group
                        var resolvedPrincipal = _utils.ResolveIDAndType(sidValue, computerDomain);
                        if (resolvedPrincipal != null) results.Add(resolvedPrincipal);
                    }

                    ret.Collected = true;
                    ret.LocalNames = names.ToArray();
                    ret.Results = results.ToArray();
                    yield return ret;
                }
            }
        }

        private TypedPrincipal ResolveDomainControllerPrincipal(string sid, string computerDomain)
        {
            //If the server is a domain controller and we have a well known group, use the domain value
            if (_utils.GetWellKnownPrincipal(sid, computerDomain, out var wellKnown))
                return wellKnown;
            return _utils.ResolveIDAndType(sid, computerDomain);
        }

        private bool ConvertLocalWellKnownPrincipal(SecurityIdentifier sid, string machineSid, string computerDomain, out TypedPrincipal principal)
        {
            if (WellKnownPrincipal.GetWellKnownPrincipal(sid.Value, out var common))
            {
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

        private NamedPrincipal ResolveGroupName(string baseName, string computerName, SecurityIdentifier machineSid,
            string domainName, int groupRid, bool isDc, bool isBuiltIn)
        {
            if (isDc)
            {
                if (isBuiltIn)
                {
                    //If this is the builtin group on the DC, the groups correspond to the domain well known groups
                    _utils.GetWellKnownPrincipal($"S-1-5-32-{groupRid}".ToUpper(), domainName, out var principal);
                    return new NamedPrincipal
                    {
                        ObjectId = principal.ObjectIdentifier,
                        PrincipalName = "IGNOREME"
                    };
                }

                if (machineSid == null)
                    return null;
                //We shouldn't hit this provided our isDC logic is correct since we're skipping non-builtin groups
                return new NamedPrincipal
                {
                    ObjectId = $"{machineSid}-{groupRid}".ToUpper(),
                    PrincipalName = "IGNOREME"
                };
            }

            if (machineSid == null)
                return null;
            //Take the local machineSid, append the groupRid, and make a name from the group name + computername
            return new NamedPrincipal
            {
                ObjectId = $"{machineSid}-{groupRid}",
                PrincipalName = $"{baseName}@{computerName}".ToUpper()
            };
        }

        private void SendComputerStatus(CSVComputerStatus status)
        {
            ComputerStatusEvent?.Invoke(status);
        }
    }
}