using System;

namespace SharpHoundCommonLib {
    public class LdapResult<T> : Result<T>
    {
        public string QueryInfo { get; set; }

        protected LdapResult(T value, bool success, string error, string queryInfo) : base(value, success, error) {
            QueryInfo = queryInfo;
        }
    
        public static LdapResult<T> Ok(T value) {
            return new LdapResult<T>(value, true, string.Empty, null);
        }

        public static LdapResult<T> Fail(string message, LdapQueryParameters queryInfo) {
            return new LdapResult<T>(default, false, message, queryInfo.GetQueryInfo());
        }
    }
}