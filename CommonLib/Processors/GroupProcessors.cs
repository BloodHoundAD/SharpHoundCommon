using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using CommonLib.Enums;
using CommonLib.Output;

namespace CommonLib.Processors
{
    public class GroupProcessors
    {
        public static async IAsyncEnumerable<TypedPrincipal> ReadGroupMembers(SearchResultEntry entry)
        {
            var domain = Helpers.DistinguishedNameToDomain(entry.DistinguishedName);
            var groupSid = entry.GetSid();
            
            Cache.AddConvertedValue(entry.DistinguishedName, groupSid);
            Cache.AddType(groupSid, Label.Group);

            var members = entry.GetPropertyAsArray("member");

            // If our returned array has a length of 0, one of two things is happening
            // The first possibility we'll look at is we need to use ranged retrieval, because AD will not return
            if (members.Length == 0)
            {
                foreach (var member in LDAPUtils.DoRangedRetrieval(entry.DistinguishedName, "member"))
                {
                    var memberDomain = Helpers.DistinguishedNameToDomain(member);
                    var res = await LDAPUtils.Instance.ResolveDistinguishedName(member);

                    if (res == null)
                    {
                        
                    }
                    else
                    {
                        yield return res;
                    }
                }
            }
            else
            {
                foreach (var member in members)
                {
                    var res = await LDAPUtils.Instance.ResolveDistinguishedName(member);

                    if (res == null)
                    {
                        
                    }
                    else
                    {
                        yield return res;
                    }
                }
            }
        }
    }
}