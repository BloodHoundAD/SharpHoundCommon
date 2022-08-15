using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundRPC;
using SharpHoundRPC.Shared;
using SharpHoundRPC.Wrappers;

namespace SharpHoundCommonLib.Processors
{
    public class LocalGroupProcessor
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

        public LocalGroupProcessor(ILDAPUtils utils, ILogger log = null)
        {
            _utils = utils;
            _log = log ?? Logging.LogProvider.CreateLogger("LocalGroupProcessor");
        }

        public IEnumerable<LocalGroupAPIResult> GetLocalGroups(SAMServer server, string computerDomainSid, string computerDomain)
        {
            var groupCache = new ConcurrentBag<LocalGroupAPIResult>();
            var typeCache = new ConcurrentDictionary<string, CachedLocalItem>();
            var computerSid = new SecurityIdentifier(computerDomainSid);

            var machineSid = server.GetMachineSid().ValueOrDefault;
            var getDomainsResult = server.GetDomains();
            if (getDomainsResult.IsFailed)
            {
                SendComputerStatus(new CSVComputerStatus
                {
                    Task = "GetDomains",
                    ComputerName = server.ComputerName,
                    Status = getDomainsResult.
                });
                yield break;
            }
            foreach (var domainResult in server.GetDomains())
            {
                var ret = new LocalGroupAPIResult
                {
                    Name = domainResult.Name,
                    GroupRID = domainResult.Rid,
                };
                
                try
                {
                    var domain = server.OpenDomain(domainResult.Name);; 
                    foreach (var alias in domain.GetAliases())
                    {
                        var results = new List<TypedPrincipal>();
                        var names = new List<NamedPrincipal>();
                        using var localGroup = domain.OpenAlias(alias.Rid);
                        foreach (var securityIdentifier in localGroup.GetMembers())
                        {
                            if (IsSidFiltered(securityIdentifier))
                                continue;

                            var sidValue = securityIdentifier.Value;

                            if (server.IsDomainController(computerSid))
                            {
                                if (_utils.GetWellKnownPrincipal(sidValue, computerDomain,
                                        out var wellKnown))
                                {
                                    results.Add(wellKnown);
                                }
                                else
                                {
                                    results.Add(_utils.ResolveIDAndType(sidValue, computerDomain));
                                }
                            }
                            else
                            {
                                if (WellKnownPrincipal.GetWellKnownPrincipal(sidValue,
                                        out var wellKnown))
                                {
                                    wellKnown.ObjectIdentifier = $"{machineSid.Value}-{securityIdentifier.Rid()}";
                                    wellKnown.ObjectType = wellKnown.ObjectType switch
                                    {
                                        Label.User => Label.LocalUser,
                                        Label.Group => Label.LocalGroup,
                                        _ => wellKnown.ObjectType
                                    };
                                    results.Add(wellKnown);
                                } else
                                {
                                    if (securityIdentifier.IsEqualDomainSid(computerSid))
                                    {
                                        results.Add(_utils.ResolveIDAndType(sidValue, computerDomain));
                                    }
                                    else
                                    {
                                        if (typeCache.TryGetValue(sidValue, out var item))
                                        {
                                            _log.LogTrace("ResolveLocalSid - Cache hit for {ID}", sidValue);
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

                                        try
                                        {
                                            var (name, use) = server.LookupUserBySid(securityIdentifier);
                                            var objectType = use switch
                                            {
                                                SharedEnums.SidNameUse.User => Label.LocalUser,
                                                SharedEnums.SidNameUse.Group => Label.LocalGroup,
                                                SharedEnums.SidNameUse.Alias => Label.LocalGroup,
                                                _ => Label.Base
                                            };
                                            
                                            results.Add(new TypedPrincipal
                                            {
                                                
                                            });
                                        }
                                        catch (Exception e)
                                        {
                                            _log.LogTrace(e, "Unable to resolve local sid {SID}", securityIdentifier.Value);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                catch (RPCException e)
                {
                    ret.Collected = false;
                    ret.FailureReason = e.ToString();
                }
                yield return ret;
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