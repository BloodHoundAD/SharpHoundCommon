using System;
using System.Collections.Generic;
using System.Security.Principal;

namespace CommonLib.LDAPQuery
{
    public abstract class FilterBase
    {
        protected List<string> _customFilters;
        protected List<string> _interpretedFilters;
        private bool _sidAdded;

        protected FilterBase()
        {
            _customFilters = new List<string>();
            _interpretedFilters = new List<string>();
        }

        protected FilterBase AddCustom(string filter)
        {
            if (filter.StartsWith("(") && filter.EndsWith(")"))
            {
                _customFilters.Add(filter);    
            }
            else
            {
                throw new InvalidFilterException(filter);
            }
            
            return this;
        }

        protected FilterBase AddSid(string sid)
        {
            if (_sidAdded)
                throw new Exception("Cannot add multiple SID filters");

            _sidAdded = true;
            var securityIdentifier = new SecurityIdentifier(sid);
            var hSid = Helpers.ConvertSidToHexSid(securityIdentifier.Value);
            _customFilters.Add($"(objectsid={hSid})");
            return this;
        }

        public abstract string GetFilter();

        public void ClearCustom()
        {
            _customFilters = new List<string>();
            _sidAdded = false;
        }
    }
}