namespace CommonLib.LDAPQuery
{
    public class DomainFilter : FilterBase
    {
        public override string GetFilter()
        {
            if (_customFilters.Count == 0)
            {
                return "(objectclass=domain)";
            }
            
            var custom = string.Join("", _customFilters);
            
            return $"(&(objectclass=domain){custom})";
        }
    }
}