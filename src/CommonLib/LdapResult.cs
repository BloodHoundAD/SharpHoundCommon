using System;

namespace SharpHoundCommonLib {
    public class LdapResult<T> : Result<T>
    {
        public string QueryInfo { get; set; }
        public int ErrorCode { get; set; }

        protected LdapResult(T value, bool success, string error, string queryInfo, int errorCode) : base(value, success, error) {
            QueryInfo = queryInfo;
            ErrorCode = errorCode;
        }
    
        public new static LdapResult<T> Ok(T value) {
            return new LdapResult<T>(value, true, string.Empty, null, 0);
        }
        
        public new static LdapResult<T> Fail() {
            return new LdapResult<T>(default, false, string.Empty, null, 0);
        }

        public static LdapResult<T> Fail(string message, LdapQueryParameters queryInfo) {
            return new LdapResult<T>(default, false, message, queryInfo.GetQueryInfo(), 0);
        }
        
        public static LdapResult<T> Fail(string message, LdapQueryParameters queryInfo, int errorCode) {
            return new LdapResult<T>(default, false, message, queryInfo.GetQueryInfo(), errorCode);
        }
    }
}