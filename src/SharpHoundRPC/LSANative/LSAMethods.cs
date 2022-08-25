using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using SharpHoundRPC.Handles;
using SharpHoundRPC.Shared;

namespace SharpHoundRPC.LSANative
{
    [SuppressUnmanagedCodeSecurity]
    public class LSAMethods
    {
        internal static (NtStatus status, LSAHandle policyHandle) LsaOpenPolicy(string computerName,
            LSAEnums.LsaOpenMask desiredAccess)
        {
            var us = new SharedStructs.UnicodeString(computerName);
            var objectAttributes = default(LSAStructs.ObjectAttributes);
            var status = LsaOpenPolicy(ref us, ref objectAttributes, desiredAccess, out var policyHandle);

            return (status, policyHandle);
        }

        [DllImport("advapi32.dll")]
        private static extern NtStatus LsaOpenPolicy(
            ref SharedStructs.UnicodeString server,
            ref LSAStructs.ObjectAttributes objectAttributes,
            LSAEnums.LsaOpenMask desiredAccess,
            out LSAHandle policyHandle
        );

        [DllImport("advapi32.dll")]
        internal static extern NtStatus LsaClose(
            IntPtr handle
        );

        [DllImport("advapi32.dll")]
        internal static extern NtStatus LsaFreeMemory(
            IntPtr buffer
        );

        internal static (NtStatus status, LSAPointer pointer) LsaQueryInformationPolicy(LSAHandle policyHandle,
            LSAEnums.LSAPolicyInformation policyInformation)
        {
            var status = LsaQueryInformationPolicy(policyHandle, policyInformation, out var pointer);

            return (status, pointer);
        }

        [DllImport("advapi32.dll")]
        private static extern NtStatus LsaQueryInformationPolicy(
            LSAHandle policyHandle,
            LSAEnums.LSAPolicyInformation policyInformation,
            out LSAPointer buffer
        );

        internal static (NtStatus status, LSAPointer sids, int count) LsaEnumerateAccountsWithUserRight(
            LSAHandle policyHandle,
            string userRight)
        {
            var arr = new SharedStructs.UnicodeString[1];
            arr[0] = new SharedStructs.UnicodeString(userRight);

            var status = LsaEnumerateAccountsWithUserRight(policyHandle, arr, out var sids, out var count);

            return (status, sids, count);
        }

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern NtStatus LsaEnumerateAccountsWithUserRight(
            LSAHandle policyHandle,
            SharedStructs.UnicodeString[] userRight,
            out LSAPointer sids,
            out int count
        );

        internal static (NtStatus status, LSAPointer referencedDomains, LSAPointer names, int count)
            LsaLookupSids(LSAHandle policyHandle,
                LSAPointer sids, int count)
        {
            var status = LsaLookupSids(policyHandle, count, sids, out var referencedDomains, out var names);
            return (status, referencedDomains, names, count);
        }

        internal static (NtStatus status, LSAPointer referencedDomains, LSAPointer names, int count)
            LsaLookupSids(LSAHandle policyHandle,
                SecurityIdentifier[] sids)
        {
            var count = sids.Length;
            if (count == 0)
                return (NtStatus.StatusInvalidParameter, null, null, 0);

            var gcHandles = new GCHandle[count];
            var pSids = new IntPtr[count];

            for (var i = 0; i < count; i++)
            {
                var sid = sids[i];
                var b = new byte[sid.BinaryLength];
                sid.GetBinaryForm(b, 0);
                gcHandles[i] = GCHandle.Alloc(b, GCHandleType.Pinned);
                pSids[i] = gcHandles[i].AddrOfPinnedObject();
            }

            try
            {
                var status = LsaLookupSids(policyHandle, count, pSids, out var referencedDomains, out var names);
                return (status, referencedDomains, names, count);
            }
            finally
            {
                foreach (var handle in gcHandles)
                    if (handle.IsAllocated)
                        handle.Free();
            }
        }

        [DllImport("advapi32.dll")]
        private static extern NtStatus LsaLookupSids(
            LSAHandle policyHandle,
            int count,
            LSAPointer sidArray,
            out LSAPointer referencedDomains,
            out LSAPointer names
        );

        [DllImport("advapi32.dll")]
        private static extern NtStatus LsaLookupSids(
            LSAHandle policyHandle,
            int count,
            [MarshalAs(UnmanagedType.LPArray)] IntPtr[] sidArray,
            out LSAPointer referencedDomains,
            out LSAPointer names
        );
    }
}