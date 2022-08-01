using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using FluentResults;
using SharpHoundRPC.Handles;
using SharpHoundRPC.SAMRPCNative;
using SharpHoundRPC.Shared;

namespace SharpHoundRPC.Wrappers
{
    public class SAMServer : SAMBase
    {
        private readonly string _computerName;
        private SecurityIdentifier _cachedMachineSid;
        private readonly ConcurrentDictionary<string, SAMDomain> _domainHandleCache;

        public SAMServer(string computerName, SAMHandle handle) : base(handle)
        {
            _computerName = computerName;
            _domainHandleCache = new ConcurrentDictionary<string, SAMDomain>();
        }

        public static Result<SAMServer> OpenServer(string computerName, SAMEnums.SamAccessMasks requestedConnectAccess =
            SAMEnums.SamAccessMasks.SamServerConnect |
            SAMEnums.SamAccessMasks
                .SamServerEnumerateDomains |
            SAMEnums.SamAccessMasks.SamServerLookupDomain)
        {
            var (status, handle) = SAMMethods.SamConnect(computerName, requestedConnectAccess);

            return status.IsError()
                ? Result.Fail($"SAMConnect returned {status}")
                : Result.Ok(new SAMServer(computerName, handle));
        }

        public Result<IEnumerable<(string Name, int Rid)>> GetDomains()
        {
            var (status, rids) = SAMMethods.SamEnumerateDomainsInSamServer(Handle);
            return status.IsError() ? Result.Fail($"SamEnumerateDomainsInSamServer returned {status}") : Result.Ok(rids.Select(x => (x.Name.ToString(), x.Rid)));
        }

        public Result<SecurityIdentifier> LookupDomain(string name)
        {
            var (status, sid) = SAMMethods.SamLookupDomainInSamServer(Handle, name);
            return status.IsError() ? Result.Fail($"SamLookupDomainInSamServer returned {status}") : Result.Ok(sid);
        }

        public Result<SecurityIdentifier> GetMachineSid(string testName = null)
        {
            if (_cachedMachineSid != null)
                return _cachedMachineSid;

            SecurityIdentifier sid = null;

            if (testName != null)
            {
                var result = LookupDomain(testName);
                if (result.IsSuccess)
                {
                    sid = result.Value;
                }
            }

            if (sid == null)
            {
                var domainResult = GetDomains();
                if (domainResult.IsSuccess)
                {
                    var result = LookupDomain(domainResult.Value.FirstOrDefault().Name);
                    if (result.IsSuccess)
                    {
                        sid = result.Value;
                    }
                }
            }

            if (sid == null) return Result.Fail("Unable to get machine sid");
            _cachedMachineSid = sid;
            return Result.Ok(sid);

        }

        public bool IsDomainController(SecurityIdentifier domainMachineSid)
        {
            return domainMachineSid.AccountDomainSid.Equals(GetMachineSid().AccountDomainSid);
        }
        
        public (string Name, SharedEnums.SidNameUse Type) LookupUserBySid(SecurityIdentifier securityIdentifier)
        {
            var domain = OpenDomain(securityIdentifier);
            return domain.LookupUserByRid(securityIdentifier.Rid());
        }

        public SAMDomain OpenDomain(string domainName, SAMEnums.DomainAccessMask requestedDomainAccess =
            SAMEnums.DomainAccessMask.Lookup |
            SAMEnums.DomainAccessMask.ListAccounts)
        {
            var sid = LookupDomain(domainName);
            if (_domainHandleCache.TryGetValue(sid.Value, out var domain))
            {
                return domain;
            }
            
            domain = SAMMethods.SamOpenDomain(Handle, sid, requestedDomainAccess);
            _domainHandleCache.TryAdd(sid.Value, domain);
            return domain;
        }

        public SAMDomain OpenDomain(SecurityIdentifier securityIdentifier,
            SAMEnums.DomainAccessMask requestedDomainAccess =
                SAMEnums.DomainAccessMask.Lookup |
                SAMEnums.DomainAccessMask.ListAccounts)
        {
            if (_domainHandleCache.TryGetValue(securityIdentifier.Value, out var domain))
            {
                return domain;
            }
            domain = SAMMethods.SamOpenDomain(Handle, securityIdentifier, requestedDomainAccess);
            _domainHandleCache.TryAdd(securityIdentifier.Value, domain);
            return domain;
        }

        protected override void Dispose(bool disposing)
        {
            foreach (var domainHandle in _domainHandleCache.Values)
            {
                domainHandle.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}