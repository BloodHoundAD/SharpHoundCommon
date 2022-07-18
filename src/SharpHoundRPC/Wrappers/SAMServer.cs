using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using SharpHoundRPC.Handles;
using SharpHoundRPC.SAMRPCNative;

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

        public static SAMServer OpenServer(string computerName, SAMEnums.SamAccessMasks requestedConnectAccess =
            SAMEnums.SamAccessMasks.SamServerConnect |
            SAMEnums.SamAccessMasks
                .SamServerEnumerateDomains |
            SAMEnums.SamAccessMasks.SamServerLookupDomain)
        {
            var handle = SAMMethods.SamConnect(computerName, requestedConnectAccess);
            return new SAMServer(computerName, handle);
        }

        public IEnumerable<(string Name, int Rid)> GetDomains()
        {
            return SAMMethods.SamEnumerateDomainsInSamServer(Handle)
                .Select(result => (result.Name.ToString(), result.Rid));
        }

        public SecurityIdentifier LookupDomain(string name)
        {
            return SAMMethods.SamLookupDomainInSamServer(Handle, name);
        }

        public SecurityIdentifier GetMachineSid(string testName = null)
        {
            if (_cachedMachineSid != null)
                return _cachedMachineSid;

            SecurityIdentifier sid;

            if (testName != null)
                try
                {
                    sid = LookupDomain(testName);
                    _cachedMachineSid = sid;
                    return sid;
                }
                catch
                {
                    // ignored
                }


            var domain = GetDomains().FirstOrDefault();
            sid = LookupDomain(domain.Name);
            _cachedMachineSid = sid;
            return sid;
        }

        public bool IsDomainController(SecurityIdentifier domainMachineSid)
        {
            return domainMachineSid.AccountDomainSid.Equals(GetMachineSid().AccountDomainSid);
        }

        public SAMDomain OpenDomain(string domainName, SAMEnums.DomainAccessMask requestedDomainAccess =
            SAMEnums.DomainAccessMask.Lookup |
            SAMEnums.DomainAccessMask.ListAccounts)
        {
            var sid = LookupDomain(domainName);
            return SAMMethods.SamOpenDomain(Handle, sid, requestedDomainAccess);
        }

        public SAMDomain OpenDomain(SecurityIdentifier securityIdentifier,
            SAMEnums.DomainAccessMask requestedDomainAccess =
                SAMEnums.DomainAccessMask.Lookup |
                SAMEnums.DomainAccessMask.ListAccounts)
        {
            return SAMMethods.SamOpenDomain(Handle, securityIdentifier, requestedDomainAccess);
        }
    }
}