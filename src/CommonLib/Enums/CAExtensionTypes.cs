namespace SharpHoundCommonLib.Enums
{
    // From https://learn.microsoft.com/en-us/windows/win32/seccertenroll/supported-extensions
    public static class CAExtensionTypes
    {
        public const string AuthorityInformationAccess = "1.3.6.1.5.5.7.1.1";
        public const string AuthorityKeyIdentifier = "2.5.29.35";
        public const string BasicConstraints = "2.5.29.19";
        public const string NameConstraints = "2.5.29.30";
        public const string EnhancedKeyUsage = "2.5.29.37";
        public const string KeyUsage = "2.5.29.15";
        public const string SubjectAlternativeNames = "2.5.29.17";
        public const string SubjectKeyIdentifier = "2.5.29.14";
    }
}