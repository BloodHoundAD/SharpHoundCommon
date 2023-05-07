using System;
using Microsoft.Win32.SafeHandles;
using SharpHoundRPC.SAMRPCNative;

namespace SharpHoundRPC.Handles
{
    public class SAMHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SAMHandle() : base(true)
        {
        }

        public SAMHandle(IntPtr handle) : base(true)
        {
            SetHandle(handle);
        }

        public SAMHandle(IntPtr handle, bool ownsHandle) : base(ownsHandle)
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            if (handle == IntPtr.Zero) return true;
            return SAMMethods.SamCloseHandle(handle) == NtStatus.StatusSuccess;
        }

        ~SAMHandle()
        {
            Dispose();
        }
    }
}