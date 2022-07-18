using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundRPC;
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

            var machineSid = server.GetMachineSid();
            foreach (var domainResult in server.GetDomains())
            {
                var ret = new LocalGroupAPIResult
                {
                    Name = domainResult.Name,
                    GroupRID = domainResult.Rid,
                };
                
                try
                {
                    var domain = server.OpenDomain(domainResult.Name);
                    foreach (var alias in domain.GetAliases())
                    {
                        var results = new List<TypedPrincipal>();
                        var localGroup = domain.OpenAlias(alias.Rid);
                        foreach (var securityIdentifier in localGroup.GetMembers())
                        {
                            if (IsSidFiltered(securityIdentifier))
                                continue;

                            if (server.IsDomainController(computerSid))
                            {
                                if (_utils.GetWellKnownPrincipal(securityIdentifier.Value, computerDomain,
                                        out var wellKnown))
                                {
                                    results.Add(wellKnown);
                                }
                                else
                                {
                                    results.Add(_utils.ResolveIDAndType(securityIdentifier.Value, computerDomain));
                                }
                            }
                            else
                            {
                                if (WellKnownPrincipal.GetWellKnownPrincipal(securityIdentifier.Value,
                                        out var wellKnown))
                                {
                                    wellKnown.ObjectIdentifier = $"{machineSid.Value}-{securityIdentifier.Rid()}";
                                    if (wellKnown.ObjectType == Label.User)
                                        wellKnown.ObjectType = Label.LocalUser;
                                    else if (wellKnown.ObjectType == Label.Group) 
                                        wellKnown.ObjectType = Label.LocalGroup;
                                    results.Add(wellKnown);
                                } else
                                {
                                    
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
    }
}