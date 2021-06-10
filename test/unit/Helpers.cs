using System;

namespace CommonLibTest
{
    public class Helpers
    {
        internal static byte[] B64ToBytes(string base64)
        {
            return Convert.FromBase64String(base64);
        }
    }
}