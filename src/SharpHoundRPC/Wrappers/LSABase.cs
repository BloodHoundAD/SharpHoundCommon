using System;
using SharpHoundRPC.Handles;

namespace SharpHoundRPC.Wrappers
{
    public class LSABase : IDisposable
    {
        protected LSAHandle Handle;

        protected LSABase(LSAHandle handle)
        {
            Handle = handle;
        }

        public void Dispose()
        {
            Dispose(true);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing) ReleaseHandle();
        }

        protected virtual void ReleaseHandle()
        {
            Handle?.Dispose();
            Handle = null;
            //Call suppressfinalize to prevent finalization, since we've already cleaned up our own stuff
            GC.SuppressFinalize(this);
        }
    }
}