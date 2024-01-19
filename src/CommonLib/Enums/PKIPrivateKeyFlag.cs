using System;

namespace SharpHoundCommonLib.Enums
{
    // from https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/f6122d87-b999-4b92-bff8-f465e8949667
    [Flags]
    public enum PKIPrivateKeyFlag : uint
    {
        REQUIRE_PRIVATE_KEY_ARCHIVAL = 0x00000001,
        EXPORTABLE_KEY = 0x00000010,
        STRONG_KEY_PROTECTION_REQUIRED = 0x00000020,
        REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM = 0x00000040,
        REQUIRE_SAME_KEY_RENEWAL = 0x00000080,
        USE_LEGACY_PROVIDER = 0x00000100,
        ATTEST_NONE = 0x00000000,
        ATTEST_REQUIRED = 0x00002000,
        ATTEST_PREFERRED = 0x00001000,
        ATTESTATION_WITHOUT_POLICY = 0x00004000,
        EK_TRUST_ON_USE = 0x00000200,
        EK_VALIDATE_CERT = 0x00000400,
        EK_VALIDATE_KEY = 0x00000800,
        HELLO_LOGON_KEY = 0x00200000
    }
}