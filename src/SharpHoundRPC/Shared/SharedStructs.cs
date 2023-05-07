using System;
using System.Runtime.InteropServices;

namespace SharpHoundRPC.Shared
{
    public class SharedStructs
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct UnicodeString : IDisposable
        {
            private readonly ushort Length;
            private readonly ushort MaximumLength;
            private IntPtr Buffer;

            public UnicodeString(string s)
                : this()
            {
                if (s == null) return;
                Length = (ushort) (s.Length * 2);
                MaximumLength = (ushort) (Length + 2);
                Buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                if (Buffer == IntPtr.Zero) return;
                Marshal.FreeHGlobal(Buffer);
                Buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return (Buffer != IntPtr.Zero ? Marshal.PtrToStringUni(Buffer, Length / 2) : null) ??
                       throw new InvalidOperationException();
            }
        }
    }
}