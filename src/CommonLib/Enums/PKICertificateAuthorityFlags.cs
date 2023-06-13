using System;

namespace SharpHoundCommonLib.Enums
{
    [Flags]
    public enum PKIEnrollmentServiceFlags
    {
        NO_TEMPLATE_SUPPORT = 0x00000001,
        SUPPORTS_NT_AUTHENTICATION = 0x00000002,
        CA_SUPPORTS_MANUAL_AUTHENTICATION = 0x00000004,
        CA_SERVERTYPE_ADVANCED = 0x00000008
    }
}