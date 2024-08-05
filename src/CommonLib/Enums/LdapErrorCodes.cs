namespace SharpHoundCommonLib.Enums
{
    public enum LdapErrorCodes : int
    {
        Success = 0,
        InvalidCredentials = 49,
        Busy = 51,
        ServerDown = 81,
        LocalError = 82,
        KerberosAuthType = 83
    }
}