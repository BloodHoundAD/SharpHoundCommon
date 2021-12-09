using System.Collections.Generic;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib.Processors
{
    public class GroupProcessor
    {
        private readonly ILogger _log;
        private readonly ILDAPUtils _utils;

        public GroupProcessor(ILDAPUtils utils, ILogger log = null)
        {
            _utils = utils;
            _log = log ?? Logging.LogProvider.CreateLogger("GroupProc");
        }

        public IEnumerable<TypedPrincipal> ReadGroupMembers(ResolvedSearchResult result, ISearchResultEntry entry)
        {
            var members = entry.GetArrayProperty("member");
            var name = result.DisplayName;
            var dn = entry.DistinguishedName;

            return ReadGroupMembers(dn, members, name);
        }

        public IEnumerable<TypedPrincipal> ReadGroupMembers(string distinguishedName, string[] members)
        {
            return ReadGroupMembers(distinguishedName, members, string.Empty);
        }

        /// <summary>
        ///     Processes the "member" property of groups and converts the resulting list of distinguishednames to TypedPrincipals
        /// </summary>
        /// <param name="distinguishedName"></param>
        /// <param name="members"></param>
        /// <returns></returns>
        public IEnumerable<TypedPrincipal> ReadGroupMembers(string distinguishedName, string[] members,
            string objectName)
        {
            // If our returned array has a length of 0, one of two things is happening
            // The first possibility we'll look at is we need to use ranged retrieval, because AD will not return
            // more than a certain number of items. If we get nothing back from this, then the group is empty
            if (members.Length == 0)
            {
                _log.LogTrace("Member property for {distinguishedName} is empty, trying range retrieval",
                    distinguishedName);
                foreach (var member in _utils.DoRangedRetrieval(distinguishedName, "member"))
                {
                    _log.LogTrace("Got member {dn} from ranged retrieval");
                    var res = _utils.ResolveDistinguishedName(member);

                    if (res == null)
                        yield return new TypedPrincipal
                        {
                            ObjectIdentifier = member.ToUpper(),
                            ObjectType = Label.Base
                        };
                    else
                        yield return res;
                }
            }
            else
            {
                //If we're here, we just read the data directly and life is good
                foreach (var member in members)
                {
                    var res = _utils.ResolveDistinguishedName(member);

                    if (res == null)
                        yield return new TypedPrincipal
                        {
                            ObjectIdentifier = member.ToUpper(),
                            ObjectType = Label.Base
                        };
                    else
                        yield return res;
                }
            }
        }

        /// <summary>
        ///     Reads the primary group info from a user or computer object and massages it into the proper format.
        /// </summary>
        /// <param name="primaryGroupId"></param>
        /// <param name="objectId"></param>
        /// <returns></returns>
        public static string GetPrimaryGroupInfo(string primaryGroupId, string objectId)
        {
            if (primaryGroupId == null)
                return null;

            if (objectId == null)
                return null;

            try
            {
                var domainSid = new SecurityIdentifier(objectId).AccountDomainSid.Value;
                var primaryGroupSid = $"{domainSid}-{primaryGroupId}";
                return primaryGroupSid;
            }
            catch
            {
                return null;
            }
        }
    }
}