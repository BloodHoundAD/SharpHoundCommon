using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.LDAPQueries;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib.Processors
{
    public class DomainTrustProcessor
    {
        private readonly ILogger _log;
        private readonly ILdapUtilsNew _utils;

        public DomainTrustProcessor(ILdapUtilsNew utils, ILogger log = null)
        {
            _utils = utils;
            _log = log ?? Logging.LogProvider.CreateLogger("DomainTrustProc");
        }

        /// <summary>
        ///     Processes domain trusts for a domain object
        /// </summary>
        /// <param name="domain"></param>
        /// <returns></returns>
        public async IAsyncEnumerable<DomainTrust> EnumerateDomainTrusts(string domain)
        {
            await foreach (var result in _utils.Query(new LdapQueryParameters {
                                   LDAPFilter = CommonFilters.TrustedDomains,
                                   Attributes = CommonProperties.DomainTrustProps,
                                   DomainName = domain
                               }))
            {
                if (!result.IsSuccess) {
                    yield break;
                }

                var entry = result.Value;
                var trust = new DomainTrust();
                var targetSidBytes = entry.GetByteProperty(LDAPProperties.SecurityIdentifier);
                if (targetSidBytes == null || targetSidBytes.Length == 0)
                {
                    _log.LogTrace("Trust sid is null or empty for target: {Domain}", domain);
                    continue;
                }

                string sid;
                try
                {
                    sid = new SecurityIdentifier(targetSidBytes, 0).Value;
                }
                catch
                {
                    _log.LogTrace("Failed to convert bytes to SID for target: {Domain}", domain);
                    continue;
                }

                trust.TargetDomainSid = sid;

                if (int.TryParse(entry.GetProperty(LDAPProperties.TrustDirection), out var td))
                {
                    trust.TrustDirection = (TrustDirection) td;
                }
                else
                {
                    _log.LogTrace("Failed to convert trustdirection for target: {Domain}", domain);
                    continue;
                }


                TrustAttributes attributes;

                if (int.TryParse(entry.GetProperty(LDAPProperties.TrustAttributes), out var ta))
                {
                    attributes = (TrustAttributes) ta;
                }
                else
                {
                    _log.LogTrace("Failed to convert trustattributes for target: {Domain}", domain);
                    continue;
                }

                trust.IsTransitive = !attributes.HasFlag(TrustAttributes.NonTransitive);
                var name = entry.GetProperty(LDAPProperties.CanonicalName)?.ToUpper();
                if (name != null)
                    trust.TargetDomainName = name;

                trust.SidFilteringEnabled = attributes.HasFlag(TrustAttributes.FilterSids);
                trust.TrustType = TrustAttributesToType(attributes);

                yield return trust;
            }
        }

        public static TrustType TrustAttributesToType(TrustAttributes attributes)
        {
            TrustType trustType;

            if (attributes.HasFlag(TrustAttributes.WithinForest))
                trustType = TrustType.ParentChild;
            else if (attributes.HasFlag(TrustAttributes.ForestTransitive))
                trustType = TrustType.Forest;
            else if (!attributes.HasFlag(TrustAttributes.WithinForest) &&
                     !attributes.HasFlag(TrustAttributes.ForestTransitive))
                trustType = TrustType.External;
            else
                trustType = TrustType.Unknown;

            return trustType;
        }
    }
}