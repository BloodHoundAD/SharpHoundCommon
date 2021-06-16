using System;
using System.Runtime.InteropServices;
using Xunit;

namespace CommonLibTest
{
    public class Helpers
    {
        internal static byte[] B64ToBytes(string base64)
        {
            return Convert.FromBase64String(base64);
        }
    }

    public sealed class WindowsOnlyFact: FactAttribute
    {
        public WindowsOnlyFact() {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) {
                Skip = "Ignore on non-Windows platforms";
            }
        }
    }
}
