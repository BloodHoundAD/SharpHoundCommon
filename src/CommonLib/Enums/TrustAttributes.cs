using System;

namespace SharpHoundCommonLib.Enums
{
    [Flags]
    public enum TrustAttributes
    {
        NonTransitive = 0x1,
        UplevelOnly = 0x2,
        QuarantinedDomain = 0x4,
        ForestTransitive = 0x8,
        CrossOrganization = 0x10,
        WithinForest = 0x20,
        TreatAsExternal = 0x40,
        UsesRc4Encryption = 0x80,
        TrustUsesAes = 0x100,
        CrossOrganizationNoTGTDelegation = 0x200,
        PIMTrust = 0x400,
        CrossOrganizationEnableTGTDelegation = 0x800,
        DisableAuthTargetValidation = 0x1000,
        Unknown = 0x400000,
    }
}
