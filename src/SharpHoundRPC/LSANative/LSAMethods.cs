using System;
using System.Collections.Generic;
using System.Linq;
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
        internal static LSAHandle LsaOpenPolicy(string computerName, LSAEnums.LsaOpenMask desiredAccess)
        {
            var us = new SharedStructs.UnicodeString(computerName);
            var objectAttributes = default(LSAStructs.ObjectAttributes);
            var status = LsaOpenPolicy(ref us, ref objectAttributes, desiredAccess, out var handle);
            status.CheckError("LsaOpenPolicy");

            return handle;
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
            IntPtr buffer
        );

        [DllImport("advapi32.dll")]
        internal static extern NtStatus LsaFreeMemory(
            IntPtr buffer
        );

        internal static LSAPointer LsaQueryInformationPolicy(LSAHandle policyHandle,
            LSAEnums.LSAPolicyInformation policyInformation)
        {
            var status = LsaQueryInformationPolicy(policyHandle, policyInformation, out var pointer);
            status.CheckError("LSAQueryInformationPolicy");

            return pointer;
        }

        [DllImport("advapi32.dll")]
        private static extern NtStatus LsaQueryInformationPolicy(
            LSAHandle policyHandle,
            LSAEnums.LSAPolicyInformation policyInformation,
            out LSAPointer buffer
        );

        internal static IEnumerable<SecurityIdentifier> LsaEnumerateAccountsWithUserRight(LSAHandle policyHandle,
            string userRight)
        {
            var arr = new SharedStructs.UnicodeString[1];
            arr[0] = new SharedStructs.UnicodeString(userRight);

            var status = LsaEnumerateAccountsWithUserRight(policyHandle, arr, out var sids, out var count);
            status.CheckError("LsaEnumerateAccountsWithUserRight");

            return sids.GetEnumerable<SecurityIdentifier>(count);
        }

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern NtStatus LsaEnumerateAccountsWithUserRight(
            LSAHandle policyHandle,
            SharedStructs.UnicodeString[] userRight,
            out LSAPointer sids,
            out int count
        );

        internal static IEnumerable<(SecurityIdentifier SID, string Name, SharedEnums.SidNameUse Use, string Domain)>
            LsaLookupSids(LSAHandle policyHandle,
                SecurityIdentifier[] sids)
        {
            var count = sids.Length;
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
                status.CheckError("LsaLookupSids");

                var translatedNames = names.GetEnumerable<LSAStructs.LSATranslatedNames>(count).ToArray();
                var domainList = referencedDomains.GetData<LSAStructs.LSAReferencedDomains>();
                var safeDomains = new LSAPointer(domainList.Domains);
                var domains = safeDomains.GetEnumerable<LSAStructs.LSATrustInformation>(domainList.Entries).ToArray();
                for (var i = 0; i < count; i++)
                    yield return (sids[i], translatedNames[i].Name.ToString(), translatedNames[i].Use,
                        domains[translatedNames[i].DomainIndex].Name.ToString());
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
            [MarshalAs(UnmanagedType.LPArray)] IntPtr[] sidArray,
            out LSAPointer referencedDomains,
            out LSAPointer names
        );
    }
}