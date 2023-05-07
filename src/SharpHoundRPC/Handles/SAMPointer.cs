using System;
using SharpHoundRPC.SAMRPCNative;

namespace SharpHoundRPC.Handles
{
    public class SAMPointer : BasePointer
    {
        public SAMPointer() : base(true)
        {
        }

        public SAMPointer(IntPtr handle) : base(handle, true)
        {
        }

        public SAMPointer(IntPtr handle, bool ownsHandle) : base(handle, ownsHandle)
        {
        }

        protected override bool ReleaseHandle()
        {
            return SAMMethods.SamFreeMemory(handle) == NtStatus.StatusSuccess;
        }
    }
}