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

        public IEnumerable<LocalGroupAPIResult> GetLocalGroups(string computerName, string computerDomainSid,
            string computerDomain)
        {
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
            var computerSid = new SecurityIdentifier(computerDomainSid);

            if (!Cache.GetMachineSid(computerDomainSid, out var machineSid))
            {
                var getMachineSidResult = server.GetMachineSid();
                if (getMachineSidResult.IsFailed)
                {
                    machineSid = "UNKNOWN";
                }
                else
                {
                    machineSid = getMachineSidResult.Value.Value;
                    Cache.AddMachineSid(computerDomainSid, machineSid);
                }
            }


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

            var isDc = server.IsDomainController(computerSid);

            foreach (var domainResult in getDomainsResult.Value)
            {
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
                    var resolvedName = ResolveGroupName(alias.Name, computerName, machineSid, computerDomain, alias.Rid, isDc,
                        domainResult.Name.Equals("builtin", StringComparison.OrdinalIgnoreCase));
                    var ret = new LocalGroupAPIResult
                    {
                        Name = resolvedName.PrincipalName,
                        ObjectIdentifier = resolvedName.ObjectId
                    };
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
                    }

                    var results = new List<TypedPrincipal>();
                    var names = new List<NamedPrincipal>();

                    var localGroup = openAliasResult.Value;
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
                    }

                    foreach (var securityIdentifier in getMembersResult.Value)
                    {
                        if (IsSidFiltered(securityIdentifier))
                            continue;

                        var sidValue = securityIdentifier.Value;

                        if (server.IsDomainController(computerSid))
                        {
                            if (_utils.GetWellKnownPrincipal(sidValue, computerDomain, out var wellKnown))
                                results.Add(wellKnown);
                            else
                                results.Add(_utils.ResolveIDAndType(sidValue, computerDomain));
                        }
                        else
                        {
                            if (WellKnownPrincipal.GetWellKnownPrincipal(sidValue, out var wellKnown))
                            {
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

                    ret.LocalNames = names.ToArray();
                    ret.Results = results.ToArray();
                    yield return ret;
                }
            }
        }

        private NamedPrincipal ResolveGroupName(string baseName, string computerName, string machineSid, string domainName, int groupRid, bool isDc, bool isBuiltIn)
        {
            if (isDc)
            {
                if (isBuiltIn)
                {
                    _utils.GetWellKnownPrincipal($"S-1-5-32-{groupRid}".ToUpper(), domainName, out var principal);
                    return new NamedPrincipal
                    {
                        ObjectId = principal.ObjectIdentifier,
                        PrincipalName = "IGNOREME"
                    };
                }

                return new NamedPrincipal
                {
                    ObjectId = $"{machineSid}-{groupRid}".ToUpper(),
                    PrincipalName = "IGNOREME"
                };
            }

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