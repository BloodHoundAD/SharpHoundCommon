using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Security.Principal;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.LDAPQueries;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib.Processors
{
    public class DomainTrustProcessor
    {
        private readonly ILDAPUtils _utils;
        public DomainTrustProcessor(ILDAPUtils utils)
        {
            _utils = utils;
        }
        /// <summary>
        /// Processes domain trusts for a domain object
        /// </summary>
        /// <param name="domain"></param>
        /// <returns></returns>
        public IEnumerable<DomainTrust> EnumerateDomainTrusts(string domain)
        {
            var query = CommonFilters.TrustedDomains;
            foreach (var result in _utils.QueryLDAP(query, SearchScope.Subtree, CommonProperties.DomainTrustProps, domain))
            {
                var trust = new DomainTrust();
                var targetSidBytes = result.GetPropertyAsBytes("securityIdentifier");
                if (targetSidBytes == null || targetSidBytes.Length == 0)
                    continue;
                string sid;
                try
                {
                    sid = new SecurityIdentifier(targetSidBytes, 0).Value;
                }
                catch
                {
                    continue;
                }

                trust.TargetDomainSid = sid;

                if (int.TryParse(result.GetProperty("trustdirection"), out var td))
                {
                    trust.TrustDirection = (TrustDirection) td;
                }
                else
                {
                    continue;
                }

                TrustAttributes attributes;

                if (int.TryParse(result.GetProperty("trustattributes"), out var ta))
                {
                    attributes = (TrustAttributes) ta;
                }
                else
                {
                    continue;
                }

                trust.IsTransitive = (attributes & TrustAttributes.NonTransitive) == 0;
                var name = result.GetProperty("cn")?.ToUpper();
                if (name != null)
                    trust.TargetDomainName = name;

                trust.SidFilteringEnabled = (attributes & TrustAttributes.FilterSids) != 0;

                TrustType trustType;
                
                if ((attributes & TrustAttributes.WithinForest) != 0)
                {
                    trustType = TrustType.ParentChild;
                }
                else if ((attributes & TrustAttributes.ForestTransitive) != 0)
                {
                    trustType = TrustType.Forest;
                }
                else if ((attributes & TrustAttributes.TreatAsExternal) != 0 ||
                         (attributes & TrustAttributes.CrossOrganization) != 0)
                {
                    trustType = TrustType.External;
                }
                else
                {
                    trustType = TrustType.Unknown;
                }

                trust.TrustType = trustType;

                yield return trust;
            }
        }
    }
}