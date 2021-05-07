using System.Collections.Generic;

namespace CommonLib.LDAPQuery
{
    public class Query
    {
        private readonly List<string> _filterParts = new();

        public Query AddAllObjects(params string[] conditions)
        {
            if (conditions.Length == 0)
            {
                _filterParts.Add("(objectclass=*)");    
            }
            else
            {
                _filterParts.Add($"(&(objectclass=*){string.Join("", conditions)})");
            }
            
            return this;
        }

        public Query AddUsers(string extraQuery = null)
        {
            if (extraQuery != null)
            {
                _filterParts.Add("(&(samaccounttype=805306368))");
            }
            else
            {
                _filterParts.Add("(samaccounttype=805306368)");    
            }

            return this;
        }

        public Query AddGroups()
        {
            _filterParts.Add("(|(samaccounttype=268435456)(samaccounttype=268435457)(samaccounttype=536870912)(samaccounttype=536870913))");

            return this;
        }

        public Query AddGPOs(bool needsFilePath = false)
        {
            _filterParts.Add($"(&(objectcategory=groupPolicyContainer)(flags=*){(needsFilePath ? "(gpcfilesyspath=*)" : "")})");

            return this;
        }

        public Query AddOUs()
        {
            _filterParts.Add("(objectcategory=organizationalUnit)");

            return this;
        }

        public Query AddDomains()
        {
            _filterParts.Add("(objectclass=domain)");

            return this;
        }

        public Query AddContainers()
        {
            _filterParts.Add("(objectClass=container)");

            return this;
        }

        public Query AddComputers(bool enabledOnly = false)
        {
            if (enabledOnly)
            {
                _filterParts.Add("(&(sAMAccountType=805306369)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))");
            }
            else
            {
                _filterParts.Add("(samaccounttype=805306369)");
            }

            return this;
        }

        public Query AddFilter(string filter)
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