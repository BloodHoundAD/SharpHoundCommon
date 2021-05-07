namespace CommonLib.LDAPQuery
{
    public class UserFilter : FilterBase
    {
        private bool _requireSPN;
        
        public UserFilter RequireSPN(bool requireSPN = true)
        {
            _requireSPN = requireSPN;
            return this;
        }
        
        public override string GetFilter()
        {
            if (_customFilters.Count == 0)
            {
                if (_requireSPN)
                {
                    return "(&(samaccounttype=805306368)(serviceprincipalname=*))";
                }

                return "(samaccounttype=805306368)";
            }

            var custom = string.Join("", _customFilters);

            if (_requireSPN)
            {
                return $"(&(samaccounttype=805306368)(serviceprincipalname=*){custom})";
            }

            return $"(&(samaccounttype=805306368){custom})";
        }
    }
}