using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib.Processors {
    public class GroupProcessor {
        private readonly ILogger _log;
        private readonly ILdapUtils _utils;

        public GroupProcessor(ILdapUtils utils, ILogger log = null) {
            _utils = utils;
            _log = log ?? Logging.LogProvider.CreateLogger("GroupProc");
        }

        public IAsyncEnumerable<TypedPrincipal> ReadGroupMembers(ResolvedSearchResult result, IDirectoryObject entry) {
            if (entry.TryGetArrayProperty(LDAPProperties.Members, out var members) &&
                entry.TryGetDistinguishedName(out var dn)) {
                return ReadGroupMembers(dn, members, result.DisplayName);
            }

            return AsyncEnumerable.Empty<TypedPrincipal>();
        }

        /// <summary>
        ///     Processes the "member" property of groups and converts the resulting list of distinguishednames to TypedPrincipals
        /// </summary>
        /// <param name="distinguishedName"></param>
        /// <param name="members"></param>
        /// <param name="objectName"></param>
        /// <returns></returns>
        public async IAsyncEnumerable<TypedPrincipal> ReadGroupMembers(string distinguishedName, string[] members,
            string objectName = "") {
            _log.LogDebug("Running Group Membership Enumeration for {ObjectName}", objectName);
            // If our returned array has a length of 0, one of two things is happening
            // The first possibility we'll look at is we need to use ranged retrieval, because AD will not return
            // more than a certain number of items. If we get nothing back from this, then the group is empty
            if (members.Length == 0) {
                _log.LogDebug("Member property for {ObjectName} is empty, trying range retrieval",
                    objectName);
                await foreach (var result in _utils.RangedRetrieval(distinguishedName, "member")) {
                    if (!result.IsSuccess) {
                        _log.LogDebug("Failure during ranged retrieval for {ObjectName}: {Message}", objectName, result.Error);
                        yield break;
                    }

                    var member = result.Value;
                    _log.LogTrace("Got member {DN} for {ObjectName} from ranged retrieval", member, objectName);
                    if (await _utils.ResolveDistinguishedName(member) is (true, var res) &&
                        !Helpers.IsSidFiltered(res.ObjectIdentifier)) {
                        yield return res;
                    } else {
                        yield return new TypedPrincipal(member.ToUpper(), Label.Base);
                    }
                }
            } else {
                //If we're here, we just read the data directly and life is good
                foreach (var member in members) {
                    _log.LogTrace("Got member {DN} for {ObjectName}", member, objectName);
                    if (await _utils.ResolveDistinguishedName(member) is (true, var res) &&
                        !Helpers.IsSidFiltered(res.ObjectIdentifier)) {
                        yield return res;
                    } else {
                        yield return new TypedPrincipal(member.ToUpper(), Label.Base);
                    }
                }
            }
        }

        /// <summary>
        ///     Reads the primary group info from a user or computer object and massages it into the proper format.
        /// </summary>
        /// <param name="primaryGroupId"></param>
        /// <param name="objectId"></param>
        /// <returns></returns>
        public static string GetPrimaryGroupInfo(string primaryGroupId, string objectId) {
            if (primaryGroupId == null)
                return null;

            if (objectId == null)
                return null;

            try {
                var domainSid = new SecurityIdentifier(objectId).AccountDomainSid.Value;
                var primaryGroupSid = $"{domainSid}-{primaryGroupId}";
                return primaryGroupSid;
            } catch {
                return null;
            }
        }
    }
}