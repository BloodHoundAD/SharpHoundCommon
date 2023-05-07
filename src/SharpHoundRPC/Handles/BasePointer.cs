using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace SharpHoundRPC.Handles
{
    public abstract class BasePointer : SafeHandleZeroOrMinusOneIsInvalid
    {
        protected BasePointer() : base(true)
        {
        }

        protected BasePointer(bool ownsHandle) : base(ownsHandle)
        {
        }

        protected BasePointer(IntPtr handle) : base(true)
        {
            SetHandle(handle);
        }

        protected BasePointer(IntPtr handle, bool ownsHandle) : base(ownsHandle)
        {
            SetHandle(handle);
        }

        public IEnumerable<T> GetEnumerable<T>(int count)
        {
            for (var i = 0; i < count; i++)
                if (typeof(T) == typeof(int))
                    yield return (T) (object) ReadInt32(i);
                else if (typeof(T) == typeof(long))
                    yield return (T) (object) ReadInt64(i);
                else if (typeof(T) == typeof(SecurityIdentifier))
                    yield return (T) (object) new SecurityIdentifier(ReadIntPtr(i));
                else
                    yield return Marshal.PtrToStructure<T>(handle + Marshal.SizeOf<T>() * i);
        }

        public T GetData<T>()
        {
            if (typeof(T) == typeof(int)) return (T) (object) ReadInt32();

            if (typeof(T) == typeof(long)) return (T) (object) ReadInt64();

            if (typeof(T) == typeof(SecurityIdentifier)) return (T) (object) new SecurityIdentifier(handle);

            return Marshal.PtrToStructure<T>(handle);
        }

        private int ReadInt32(int offset = 0)
        {
            return Marshal.ReadInt32(handle + offset * Marshal.SizeOf<int>());
        }

        private long ReadInt64(int offset = 0)
        {
            return Marshal.ReadInt64(handle + offset * Marshal.SizeOf<long>());
        }

        private IntPtr ReadIntPtr(int offset = 0)
        {
            return Marshal.ReadIntPtr(handle + offset * Marshal.SizeOf<IntPtr>());
        }
    }
}