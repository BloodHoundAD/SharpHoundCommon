namespace SharpHoundRPC
{
    public enum NtStatus
    {
        StatusSuccess = 0x0,
        StatusMoreEntries = 0x105,
        StatusSomeMapped = 0x107,
        StatusInvalidHandle = unchecked((int) 0xC0000008),
        StatusInvalidParameter = unchecked((int) 0xC000000D),
        StatusAccessDenied = unchecked((int) 0xC0000022),
        StatusObjectTypeMismatch = unchecked((int) 0xC0000024),
        StatusNoSuchDomain = unchecked((int) 0xC00000DF),
        StatusRpcServerUnavailable = unchecked((int) 0xC0020017),
        StatusNoSuchAlias = unchecked((int) 0xC0000151),
        StatusNoMoreEntries = unchecked((int) 0x8000001A)
    }
}