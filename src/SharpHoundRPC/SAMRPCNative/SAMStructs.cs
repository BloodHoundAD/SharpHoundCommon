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
                if (_objectName == IntPtr.Zero) return;
                Marshal.DestroyStructure(_objectName, typeof(SharedStructs.UnicodeString));
                Marshal.FreeHGlobal(_objectName);
                _objectName = IntPtr.Zero;
            }

            public int Length;
            public IntPtr RootDirectory;
            public uint Attributes;
            public IntPtr SID;
            public IntPtr Qos;
            private IntPtr _objectName;
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