using System;

namespace CommonLib.LDAPQuery
{
    public class InvalidFilterException : Exception
    {
        public InvalidFilterException()
        {
            
        }
        
        public InvalidFilterException(string filter) : base($"Invalid ldap filter: {filter}")
        {
        }
        
    }
}