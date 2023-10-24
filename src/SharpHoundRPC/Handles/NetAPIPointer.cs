using System;
using SharpHoundRPC.NetAPINative;

namespace SharpHoundRPC.Handles
{
    public class NetAPIPointer : BasePointer
    {
        public NetAPIPointer() : base(true)
        {
        }

        public NetAPIPointer(IntPtr handle) : base(handle, true)
        {
        }

        public NetAPIPointer(IntPtr handle, bool ownsHandle) : base(handle, ownsHandle)
        {
        }

        protected override bool ReleaseHandle()
        {
            if (handle == IntPtr.Zero) return true;
            return NetAPIMethods.NetApiBufferFree(handle) == NetAPIEnums.NetAPIStatus.Success;
        }
    }
}