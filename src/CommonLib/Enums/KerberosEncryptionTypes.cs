namespace SharpHoundCommonLib.Enums
{
    public class KerberosEncryptionTypes
    {
        public const int DES_CBC_CRC = 1;
        public const int DES_CBC_MD5 = 2;
        public const int RC4_HMAC_MD5 = 4;
        public const int AES128_CTS_HMAC_SHA1_96 = 8;
        public const int AES256_CTS_HMAC_SHA1_96 = 16;
    }
}