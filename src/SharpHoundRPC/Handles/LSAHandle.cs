using System;
using Microsoft.Win32.SafeHandles;
using SharpHoundRPC.LSANative;

namespace SharpHoundRPC.Handles
{
    public class LSAHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public LSAHandle() : base(true)
        {
        }

        public LSAHandle(IntPtr handle, bool ownsHandle) : base(ownsHandle)
        {
            SetHandle(handle);
        }

        public LSAHandle(bool ownsHandle) : base(true)
        {
        }

        protected override bool ReleaseHandle()
        {
            if (handle == IntPtr.Zero) return true;
            return LSAMethods.LsaClose(handle) == NtStatus.StatusSuccess;
        }

        ~LSAHandle()
        {
            Dispose();
        }
    }
}