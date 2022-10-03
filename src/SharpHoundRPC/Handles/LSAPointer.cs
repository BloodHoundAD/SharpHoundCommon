using System;
using SharpHoundRPC.LSANative;

namespace SharpHoundRPC.Handles
{
    public class LSAPointer : BasePointer
    {
        public LSAPointer() : base(true)
        {
        }

        public LSAPointer(IntPtr handle) : base(handle, true)
        {
        }

        public LSAPointer(IntPtr handle, bool ownsHandle) : base(handle, ownsHandle)
        {
        }

        protected override bool ReleaseHandle()
        {
            if (handle == IntPtr.Zero) return true;
            return LSAMethods.LsaFreeMemory(handle) == NtStatus.StatusSuccess;
        }
    }
}