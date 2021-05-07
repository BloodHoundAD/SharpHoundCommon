using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Security.Principal;
using CommonLib.Enums;
using CommonLib.Output;

namespace CommonLib.Processors
{
    public class GroupProcessors
    {
        /// <summary>
        /// Processes the "member" property of groups and converts the resulting list of distinguishednames to TypedPrincipals
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public static async IAsyncEnumerable<TypedPrincipal> ReadGroupMembers(SearchResultEntry entry)
        {
            var groupSid = entry.GetSid();
            
            Cache.AddConvertedValue(entry.DistinguishedName, groupSid);
            Cache.AddType(groupSid, Label.Group);

            var members = entry.GetPropertyAsArray("member");

            // If our returned array has a length of 0, one of two things is happening
            // The first possibility we'll look at is we need to use ranged retrieval, because AD will not return
            // more than a certain number of items. If we get nothing back from this, then the group is empty
            if (members.Length == 0)
            {
                foreach (var member in LDAPUtils.DoRangedRetrieval(entry.DistinguishedName, "member"))
                {
                    var res = await LDAPUtils.ResolveDistinguishedName(member);

                    if (res == null)
                        yield return new TypedPrincipal
                        {
                            ObjectIdentifier = member,
                            ObjectType = Label.Unknown
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
                    var res = await LDAPUtils.ResolveDistinguishedName(member);

                    if (res == null)
                        yield return new TypedPrincipal
                        {
                            ObjectIdentifier = member,
                            ObjectType = Label.Unknown
                        };
                    else
                        yield return res;
                }
            }
        }

        /// <summary>
        /// Reads the primary group info from a user or computer object and massages it into the proper format.
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public static string GetPrimaryGroupInfo(SearchResultEntry entry)
        {
            var primaryGroupId = entry.GetProperty("primarygroupid");
            if (primaryGroupId == null)
                return null;

            try
            {
                var domainSid = new SecurityIdentifier(entry.GetSid()).AccountDomainSid.Value;
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