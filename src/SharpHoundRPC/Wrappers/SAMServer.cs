using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using SharpHoundRPC.Handles;
using SharpHoundRPC.SAMRPCNative;
using SharpHoundRPC.Shared;

namespace SharpHoundRPC.Wrappers
{
    public class SAMServer : SAMBase
    {
        private readonly ConcurrentDictionary<string, SAMDomain> _domainHandleCache;
        private SecurityIdentifier _cachedMachineSid;

        public SAMServer(SAMHandle handle, string computerName) : base(handle)
        {
            _domainHandleCache = new ConcurrentDictionary<string, SAMDomain>();
            ComputerName = computerName;
        }

        public string ComputerName { get; }

        public static Result<SAMServer> OpenServer(string computerName, SAMEnums.SamAccessMasks requestedConnectAccess =
            SAMEnums.SamAccessMasks.SamServerConnect |
            SAMEnums.SamAccessMasks
                .SamServerEnumerateDomains |
            SAMEnums.SamAccessMasks.SamServerLookupDomain)
        {
            var (status, handle) = SAMMethods.SamConnect(computerName, requestedConnectAccess);

            return status.IsError()
                ? status
                : new SAMServer(handle, computerName);
        }

        public Result<IEnumerable<(string Name, int Rid)>> GetDomains()
        {
            var (status, rids) = SAMMethods.SamEnumerateDomainsInSamServer(Handle);
            return status.IsError()
                ? status
                : Result<IEnumerable<(string Name, int Rid)>>.Ok(rids.Select(x => (x.Name.ToString(), x.Rid)));
        }

        public Result<SecurityIdentifier> LookupDomain(string name)
        {
            var (status, sid) = SAMMethods.SamLookupDomainInSamServer(Handle, name);
            return status.IsError() ? status : sid;
        }

        public Result<SecurityIdentifier> GetMachineSid(string testName = null)
        {
            if (_cachedMachineSid != null)
                return _cachedMachineSid;

            SecurityIdentifier sid = null;

            if (testName != null)
            {
                var result = LookupDomain(testName);
                if (result.IsSuccess) sid = result.Value;
            }

            if (sid == null)
            {
                var domainResult = GetDomains();
                if (domainResult.IsSuccess)
                {
                    var result = LookupDomain(domainResult.Value.FirstOrDefault().Name);
                    if (result.IsSuccess) sid = result.Value;
                }
            }

            if (sid == null) return "Unable to get machine sid";
            _cachedMachineSid = sid;
            return sid;
        }

        public bool IsDomainController(SecurityIdentifier domainMachineSid)
        {
            return domainMachineSid.AccountDomainSid.Equals(GetMachineSid().Value.AccountDomainSid);
        }

        public Result<(string Name, SharedEnums.SidNameUse Type)> LookupPrincipalBySid(
            SecurityIdentifier securityIdentifier)
        {
            var openDomainResult = OpenDomain(securityIdentifier);
            if (openDomainResult.IsFailed) return $"OpenDomain returned {openDomainResult.Status}";

            var domain = openDomainResult.Value;

            return domain.LookupPrincipalByRid(securityIdentifier.Rid());
        }

        public Result<SAMDomain> OpenDomain(string domainName, SAMEnums.DomainAccessMask requestedDomainAccess =
            SAMEnums.DomainAccessMask.Lookup |
            SAMEnums.DomainAccessMask.ListAccounts)
        {
            var lookupResult = LookupDomain(domainName);
            if (lookupResult.IsFailed) return $"LookupDomain returned {lookupResult.Error}";

            var sid = lookupResult.Value;

            if (_domainHandleCache.TryGetValue(sid.Value, out var domain)) return domain;

            var (status, domainHandle) = SAMMethods.SamOpenDomain(Handle, requestedDomainAccess, sid.GetBytes());
            if (status.IsError()) return status;

            domain = new SAMDomain(domainHandle);

            _domainHandleCache.TryAdd(sid.Value, domain);
            return domain;
        }

        public Result<SAMDomain> OpenDomain(SecurityIdentifier securityIdentifier,
            SAMEnums.DomainAccessMask requestedDomainAccess =
                SAMEnums.DomainAccessMask.Lookup |
                SAMEnums.DomainAccessMask.ListAccounts)
        {
            if (_domainHandleCache.TryGetValue(securityIdentifier.Value, out var domain)) return domain;

            var (status, domainHandle) =
                SAMMethods.SamOpenDomain(Handle, requestedDomainAccess, securityIdentifier.GetBytes());
            if (status.IsError()) return status.ToString();

            domain = new SAMDomain(domainHandle);
            _domainHandleCache.TryAdd(securityIdentifier.Value, domain);
            return domain;
        }

        protected override void Dispose(bool disposing)
        {
            foreach (var domainHandle in _domainHandleCache.Values) domainHandle.Dispose();
            base.Dispose(disposing);
        }
    }
}