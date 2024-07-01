namespace SharpHoundCommonLib.Enums {
    public enum LdapFailureReason
    {
        None,
        NoData,
        FailedBind,
        FailedRequest,
        FailedAuthentication,
        AuthenticationException,
        Unknown
    }
}