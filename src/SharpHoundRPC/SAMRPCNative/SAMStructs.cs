using System;
using System.Runtime.InteropServices;
using SharpHoundRPC.Shared;

namespace SharpHoundRPC.SAMRPCNative
{
    public static class SAMStructs
    {
        public struct ObjectAttributes : IDisposable
        {
            public void Dispose()
            {
                if (objectName == IntPtr.Zero) return;
                Marshal.DestroyStructure(objectName, typeof(SharedStructs.UnicodeString));
                Marshal.FreeHGlobal(objectName);
                objectName = IntPtr.Zero;
            }

            public int len;
            public IntPtr rootDirectory;
            public uint attribs;
            public IntPtr sid;
            public IntPtr qos;
            private IntPtr objectName;
            public SharedStructs.UnicodeString ObjectName;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SamRidEnumeration
        {
            public int Rid;
            public SharedStructs.UnicodeString Name;
        }
    }
}