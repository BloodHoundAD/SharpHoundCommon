using System;
using CommonLibTest.Facades;
using SharpHoundCommonLib;

namespace CommonLibTest
{
    public class Helpers
    {
        internal static byte[] B64ToBytes(string base64)
        {
            return Convert.FromBase64String(base64);
        }

        internal static void SwapMockUtils()
        {
            LDAPUtils.Instance = new MockLDAPUtils();
        }

        internal static void RestoreMockUtils()
        {
            LDAPUtils.Instance = new LDAPUtils();
        }
    }
}