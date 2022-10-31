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

        private readonly string[] _filteredSids =
        {
            "S-1-5-2", "S-1-5-2", "S-1-5-3", "S-1-5-4", "S-1-5-6", "S-1-5-7", "S-1-2", "S-1-2-0", "S-1-5-18",
            "S-1-5-19", "S-1-5-20"
        };

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
                    Status = openServerResult.Status.ToString()
                });
                yield break;
            }

            var server = openServerResult.Value;
            var typeCache = new ConcurrentDictionary<string, CachedLocalItem>();
            var computerSid = new SecurityIdentifier(computerObjectId);

            //Try to get the machine sid for the computer if its not already cached
            if (!Cache.GetMachineSid(computerObjectId, out var machineSid))
            {
                var getMachineSidResult = server.GetMachineSid();
                if (getMachineSidResult.IsFailed)
                {
                    _log.LogWarning("MachineSid for computer {ComputerName} is unknown", computerName);
                    machineSid = "UNKNOWN";
                }
                else
                {
                    machineSid = getMachineSidResult.Value.Value;
                    Cache.AddMachineSid(computerObjectId, machineSid);
                }
            }

            //Get all available domains in the server
            var getDomainsResult = server.GetDomains();
            if (getDomainsResult.IsFailed)
            {
                SendComputerStatus(new CSVComputerStatus
                {
                    Task = "GetDomains",
                    ComputerName = computerName,
                    Status = getDomainsResult.Status.ToString()
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
                        Status = openDomainResult.Status.ToString()
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
                        Status = getAliasesResult.Status.ToString()
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
                            Status = openAliasResult.Status.ToString()
                        });
                        ret.Collected = false;
                        ret.FailureReason = $"SamOpenAliasInDomain failed with status {openAliasResult.Status}";
                        yield return ret;
                        continue;
                    }

                    var results = new List<TypedPrincipal>();
                    var names = new List<NamedPrincipal>();

                    var localGroup = openAliasResult.Value;
                    //Call GetMembersInAlias to get raw group members
                    var getMembersResult = localGroup.GetMembers();
                    if (getMembersResult.IsFailed)
                    {
                        SendComputerStatus(new CSVComputerStatus
                        {
                            Task = $"GetMembersInAlias - {alias.Name}",
                            ComputerName = computerName,
                            Status = getMembersResult.Status.ToString()
                        });
                        ret.Collected = false;
                        ret.FailureReason = $"SamGetMembersInAlias failed with status {getMembersResult.Status}";
                        yield return ret;
                        continue;
                    }

                    SendComputerStatus(new CSVComputerStatus
                    {
                        Task = $"GetMembersInAlias - {alias.Name}",
                        ComputerName = computerName,
                        Status = CSVComputerStatus.StatusSuccess
                    });

                    foreach (var securityIdentifier in getMembersResult.Value)
                    {
                        //Check if the sid is one of our filtered ones
                        if (IsSidFiltered(securityIdentifier))
                            continue;

                        var sidValue = securityIdentifier.Value;

                        if (isDomainController)
                        {
                            //If the server is a domain controller and we have a well known group, use the domain value
                            if (_utils.GetWellKnownPrincipal(sidValue, computerDomain, out var wellKnown))
                                results.Add(wellKnown);
                            //Call ResolveIDAndType for non-well known principals
                            else
                                results.Add(_utils.ResolveIDAndType(sidValue, computerDomain));
                        }
                        else
                        {
                            //Use the non-utils call to ensure we dont cache this well known principal for later output
                            if (WellKnownPrincipal.GetWellKnownPrincipal(sidValue, out var wellKnown))
                            {
                                //If we dont know our machine sid, we cant do much else
                                if (machineSid == "UNKNOWN")
                                    continue;
                                wellKnown.ObjectIdentifier = $"{machineSid}-{securityIdentifier.Rid()}";
                                wellKnown.ObjectType = wellKnown.ObjectType switch
                                {
                                    Label.User => Label.LocalUser,
                                    Label.Group => Label.LocalGroup,
                                    _ => wellKnown.ObjectType
                                };
                                results.Add(wellKnown);
                            }
                            else
                            {
                                if (securityIdentifier.IsEqualDomainSid(computerSid))
                                {
                                    results.Add(_utils.ResolveIDAndType(sidValue, computerDomain));
                                }
                                else
                                {
                                    if (typeCache.TryGetValue(sidValue, out var item))
                                    {
                                        results.Add(new TypedPrincipal
                                        {
                                            ObjectIdentifier = sidValue,
                                            ObjectType = item.Type
                                        });

                                        names.Add(new NamedPrincipal
                                        {
                                            ObjectId = sidValue,
                                            PrincipalName = item.Name
                                        });
                                    }
                                    else
                                    {
                                        var lookupUserResult = server.LookupPrincipalBySid(securityIdentifier);
                                        if (lookupUserResult.IsFailed)
                                        {
                                            _log.LogTrace("Unable to resolve local sid {SID}", sidValue);
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

                                        typeCache.TryAdd(sidValue, new CachedLocalItem(name, objectType));

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
                                    }
                                }
                            }
                        }
                    }

                    ret.Collected = true;
                    ret.LocalNames = names.ToArray();
                    ret.Results = results.ToArray();
                    yield return ret;
                }
            }
        }

        private NamedPrincipal ResolveGroupName(string baseName, string computerName, string machineSid,
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

                //We shouldn't hit this provided our isDC logic is correct since we're skipping non-builtin groups
                return new NamedPrincipal
                {
                    ObjectId = $"{machineSid}-{groupRid}".ToUpper(),
                    PrincipalName = "IGNOREME"
                };
            }

            //Take the local machineSid, append the groupRid, and make a name from the group name + computername
            return new NamedPrincipal
            {
                ObjectId = $"{machineSid}-{groupRid}",
                PrincipalName = $"{baseName}@{computerName}".ToUpper()
            };
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