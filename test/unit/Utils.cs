﻿using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace CommonLibTest
{
    public static class Utils
    {
        internal static byte[] B64ToBytes(string base64)
        {
            return Convert.FromBase64String(base64);
        }

        internal static string B64ToString(string base64)
        {
            var b = B64ToBytes(base64);
            return Encoding.UTF8.GetString(b);
        }
    }

    internal static class Extensions
    {
        internal static bool IsArray(this object obj)
        {
            var valueType = obj?.GetType();
            if (valueType == null)
                return false;
            return valueType.IsArray;
        }
    }

    public sealed class WindowsOnlyFact : FactAttribute
    {
        public WindowsOnlyFact()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) Skip = "Ignore on non-Windows platforms";
        }
    }
}