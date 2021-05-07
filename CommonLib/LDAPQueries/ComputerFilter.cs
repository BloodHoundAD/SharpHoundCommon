namespace CommonLib.LDAPQuery
{
    public class ComputerFilter : FilterBase
    {
        private bool _enabledOnly;

        public ComputerFilter EnabledOnly(bool enabled = true)
        {
            _enabledOnly = enabled;
            return this;
        }

        public override string GetFilter()
        {
            if (_customFilters.Count == 0)
            {
                if (_enabledOnly)
                {
                    return "(&(sAMAccountType=805306369)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))";
                }

                return "(samaccounttype=805306369)";
            }

            var custom = string.Join("", _customFilters);

            if (_enabledOnly)
            {
                return $"(&(sAMAccountType=805306369)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)){custom})";
            }

            return $"(&(samaccounttype=805306369){custom})";
        }
    }
}