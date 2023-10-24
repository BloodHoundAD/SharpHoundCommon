using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace SharpHoundRPC.Handles
{
    public class SAMSidArray : SAMPointer
    {
        public SAMSidArray()
        {
        }

        public SAMSidArray(IntPtr handle) : base(handle)
        {
        }

        public SAMSidArray(IntPtr handle, bool ownsHandle) : base(handle, ownsHandle)
        {
        }

        public IEnumerable<SecurityIdentifier> GetData(int count)
        {
            for (var i = 0; i < count; i++)
            {
                var rawPtr = Marshal.ReadIntPtr(handle, Marshal.SizeOf<IntPtr>() * i);
                var sid = new SecurityIdentifier(rawPtr);
                yield return sid;
            }
        }
    }
}