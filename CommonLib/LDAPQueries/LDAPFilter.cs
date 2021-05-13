using System.Collections.Generic;
using System.Linq;

namespace SharpHoundCommonLib.LDAPQueries
{
    public class LDAPFilter
    {
        private readonly List<string> _filterParts = new();

        /// <summary>
        /// Pre-filters conditions passed into filters.
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        private string[] CheckConditions(IEnumerable<string> conditions)
        {
            return conditions.Select(x =>
            {
                if (x.StartsWith("(") && x.EndsWith(")"))
                {
                    return x;
                }

                return $"({x})";
            }).ToArray();
        }

        private string BuildString(string baseFilter, params string[] conditions)
        {
            if (conditions.Length == 0)
            {
                return baseFilter;
            }

            return $"(&{baseFilter}{string.Join("", CheckConditions(conditions))})";
        }

        public LDAPFilter AddAllObjects(params string[] conditions)
        {
            _filterParts.Add(BuildString("(objectclass=*)", conditions));
            
            return this;
        }

        public LDAPFilter AddUsers(params string[] conditions)
        {
            _filterParts.Add(BuildString("(samaccounttype=805306368)", conditions));

            return this;
        }

        public LDAPFilter AddGroups(params string[] conditions)
        {
            _filterParts.Add(BuildString("(|(samaccounttype=268435456)(samaccounttype=268435457)(samaccounttype=536870912)(samaccounttype=536870913))", conditions));

            return this;
        }
        
        public LDAPFilter AddPrimaryGroups(params string[] conditions)
        {
            _filterParts.Add(BuildString("(primarygroupid=*)", conditions));

            return this;
        }

        public LDAPFilter AddGPOs(params string[] conditions)
        {
            _filterParts.Add(BuildString("(&(objectcategory=groupPolicyContainer)(flags=*))", conditions));

            return this;
        }

        public LDAPFilter AddOUs(params string[] conditions)
        {
            _filterParts.Add(BuildString("(objectcategory=organizationalUnit)", conditions));

            return this;
        }

        public LDAPFilter AddDomains(params string[] conditions)
        {
            _filterParts.Add(BuildString("(objectclass=domain)", conditions));

            return this;
        }

        public LDAPFilter AddContainers(params string[] conditions)
        {
            _filterParts.Add(BuildString("(objectClass=container)", conditions));

            return this;
        }

        public LDAPFilter AddComputers(params string[] conditions)
        {
            _filterParts.Add(BuildString("(samaccounttype=805306369)", conditions));
            return this;
        }

        public LDAPFilter AddSchemaID(params string[] conditions)
        {
            _filterParts.Add(BuildString("(schemaidguid=*)", conditions));
            return this;
        }

        public LDAPFilter AddFilter(string filter)
        {
            _filterParts.Add(filter);

            return this;
        }

        public string GetFilter()
        {
            var temp = string.Join("", _filterParts.ToArray());
            temp = _filterParts.Count == 1 ? _filterParts[0] : $"(|{temp})";

            return temp;
        }
    }
}