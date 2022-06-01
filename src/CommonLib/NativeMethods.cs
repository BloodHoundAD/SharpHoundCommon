using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Processors;

namespace SharpHoundCommonLib
{
    [ExcludeFromCodeCoverage]
    public class NativeMethods
    {
        public enum NtStatus
        {
            StatusSuccess = 0x0,
            StatusMoreEntries = 0x105,
            StatusSomeMapped = 0x107,
            StatusInvalidHandle = unchecked((int) 0xC0000008),
            StatusInvalidParameter = unchecked((int) 0xC000000D),
            StatusAccessDenied = unchecked((int) 0xC0000022),
            StatusObjectTypeMismatch = unchecked((int) 0xC0000024),
            StatusNoSuchDomain = unchecked((int) 0xC00000DF),
            StatusRpcServerUnavailable = unchecked((int) 0xC0020017),
            StatusNoSuchAlias = unchecked((int) 0xC0000151)
        }

        private const string NetWkstaUserEnumQueryName = "NetWkstaUserEnum";
        private const string NetSessionEnumQueryName = "NetSessionEnum";
        private const string NetWkstaGetInfoQueryName = "NetWkstaGetInfo";

        private const int NetWkstaUserEnumQueryLevel = 1;
        private const int NetSessionEnumLevel = 10;
        private const int NetWkstaGetInfoQueryLevel = 100;
        private readonly ILogger _log;

        public NativeMethods(ILogger log = null)
        {
            _log = log ?? Logging.LogProvider.CreateLogger("NativeMethods");
        }

        public NativeMethods()
        {
            _log = Logging.LogProvider.CreateLogger("NativeMethods");
        }

        public virtual WorkstationInfo100 CallNetWkstaGetInfo(string serverName)
        {
            var ptr = IntPtr.Zero;

            try
            {
                var result = NetWkstaGetInfo(serverName, NetWkstaGetInfoQueryLevel, out ptr);
                if (result != NERR.NERR_Success)
                    throw new APIException
                    {
                        Status = result.ToString(),
                        APICall = NetWkstaGetInfoQueryName
                    };

                var wkstaInfo = Marshal.PtrToStructure<WorkstationInfo100>(ptr);
                return wkstaInfo;
            }
            finally
            {
                if (ptr != IntPtr.Zero)
                    NetApiBufferFree(ptr);
            }
        }

        public virtual IEnumerable<SESSION_INFO_10> CallNetSessionEnum(string serverName)
        {
            var ptr = IntPtr.Zero;

            _log.LogTrace("Beginning NetSessionEnum for {ServerName}", serverName);
            try
            {
                var resumeHandle = 0;
                var result = NetSessionEnum(serverName, null, null, NetSessionEnumLevel, out ptr, -1,
                    out var entriesread,
                    out _, ref resumeHandle);

                _log.LogTrace("Result of NetSessionEnum for {ServerName} is {Result}", serverName, result);

                if (result != NERR.NERR_Success)
                    throw new APIException
                    {
                        APICall = NetSessionEnumQueryName,
                        Status = result.ToString()
                    };

                var iter = ptr;
                for (var i = 0; i < entriesread; i++)
                {
                    var data = Marshal.PtrToStructure<SESSION_INFO_10>(iter);
                    iter = (IntPtr) (iter.ToInt64() + Marshal.SizeOf<SESSION_INFO_10>());

                    yield return data;
                }
            }
            finally
            {
                if (ptr != IntPtr.Zero)
                    NetApiBufferFree(ptr);
            }
        }

        public virtual IEnumerable<WKSTA_USER_INFO_1> CallNetWkstaUserEnum(string servername)
        {
            var ptr = IntPtr.Zero;
            try
            {
                var resumeHandle = 0;
                _log.LogTrace("Beginning NetWkstaUserEnum for {ServerName}", servername);
                var result = NetWkstaUserEnum(servername, NetWkstaUserEnumQueryLevel, out ptr, -1, out var entriesread,
                    out _,
                    ref resumeHandle);

                _log.LogTrace("Result of NetWkstaUserEnum for computer {ServerName} is {Result}", servername, result);

                if (result != NERR.NERR_Success && result != NERR.ERROR_MORE_DATA)
                    throw new APIException
                    {
                        APICall = NetWkstaUserEnumQueryName,
                        Status = result.ToString()
                    };

                var iter = ptr;
                for (var i = 0; i < entriesread; i++)
                {
                    var data = Marshal.PtrToStructure<WKSTA_USER_INFO_1>(iter);
                    iter = (IntPtr) (iter.ToInt64() + Marshal.SizeOf<WKSTA_USER_INFO_1>());
                    yield return data;
                }
            }
            finally
            {
                if (ptr != IntPtr.Zero)
                    NetApiBufferFree(ptr);
            }
        }

        public virtual DOMAIN_CONTROLLER_INFO? CallDsGetDcName(string computerName, string domainName)
        {
            var ptr = IntPtr.Zero;
            try
            {
                var result = DsGetDcName(computerName, domainName, null, null,
                    (uint) (DSGETDCNAME_FLAGS.DS_IS_FLAT_NAME | DSGETDCNAME_FLAGS.DS_RETURN_DNS_NAME), out ptr);

                if (result != 0) return null;
                var info = Marshal.PtrToStructure<DOMAIN_CONTROLLER_INFO>(ptr);
                return info;
            }
            finally
            {
                if (ptr != IntPtr.Zero)
                    NetApiBufferFree(ptr);
            }
        }

        public virtual NtStatus CallSamConnect(ref UNICODE_STRING serverName, out IntPtr serverHandle,
            SamAccessMasks desiredAccess, ref OBJECT_ATTRIBUTES objectAttributes)
        {
            return SamConnect(ref serverName, out serverHandle, desiredAccess, ref objectAttributes);
        }

        internal virtual NtStatus CallSamOpenDomain(IntPtr serverHandle, DomainAccessMask desiredAccess,
            byte[] domainSid, out IntPtr domainHandle)
        {
            return SamOpenDomain(serverHandle, desiredAccess, domainSid, out domainHandle);
        }

        internal virtual NtStatus CallSamOpenAlias(IntPtr domainHandle, AliasOpenFlags desiredAccess, int aliasId,
            out IntPtr aliasHandle)
        {
            return SamOpenAlias(domainHandle, desiredAccess, aliasId, out aliasHandle);
        }

        internal virtual NtStatus CallSamGetMembersInAlias(IntPtr aliasHandle, out IntPtr members, out int count)
        {
            return SamGetMembersInAlias(aliasHandle, out members, out count);
        }

        internal virtual NtStatus CallSamLookupDomainInSamServer(IntPtr serverHandle, ref UNICODE_STRING name,
            out IntPtr sid)
        {
            return SamLookupDomainInSamServer(serverHandle, ref name, out sid);
        }

        internal virtual NtStatus CallSamEnumerateAliasesInDomain(IntPtr domainHandle, out IntPtr rids, out int count)
        {
            var enumContext = 0;
            return SamEnumerateAliasesInDomain(domainHandle, ref enumContext, out rids, -1, out count);
        }


        internal virtual NtStatus CallSamFreeMemory(IntPtr handle)
        {
            return SamFreeMemory(handle);
        }

        internal virtual NtStatus CallSamCloseHandle(IntPtr handle)
        {
            return SamCloseHandle(handle);
        }

        internal virtual NtStatus CallSamEnumerateDomainsInSamServer(IntPtr serverHandle, out IntPtr domains,
            out int count)
        {
            var enumContext = 0;
            return SamEnumerateDomainsInSamServer(serverHandle, ref enumContext, out domains, -1, out count);
        }

        internal virtual NtStatus CallLSAOpenPolicy(ref LSA_UNICODE_STRING serverName,
            ref LSA_OBJECT_ATTRIBUTES lsaObjectAttributes,
            LsaOpenMask openMask, out IntPtr policyHandle)
        {
            return LsaOpenPolicy(ref serverName, ref lsaObjectAttributes, openMask, out policyHandle);
        }

        internal virtual NtStatus CallLSAEnumerateAccountsWithUserRight(IntPtr policyHandle, string privilege,
            out IntPtr buffer,
            out int count)
        {
            var privileges = new LSA_UNICODE_STRING[1];
            privileges[0] = new LSA_UNICODE_STRING(privilege);
            return LsaEnumerateAccountsWithUserRight(policyHandle, privileges, out buffer, out count);
        }

        internal virtual NtStatus CallSamLookupIdsInDomain(IntPtr domainHandle, int[] rids, out IntPtr names,
            out IntPtr use)
        {
            var count = rids.Length;

            return SamLookupIdsInDomain(domainHandle, count, rids, out names, out use);
        }

        public virtual NtStatus CallLSAClose(IntPtr handle)
        {
            return LsaClose(handle);
        }

        public virtual NtStatus CallLSAFreeMemory(IntPtr handle)
        {
            return LsaFreeMemory(handle);
        }

        public virtual NtStatus CallLSALookupSids(IntPtr policyHandle, SecurityIdentifier[] sids,
            out IntPtr referencedDomains, out IntPtr names)
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
                return LsaLookupSids(policyHandle, (uint) count, pSids, out referencedDomains, out names);
            }
            finally
            {
                foreach (var handle in gcHandles)
                    if (handle.IsAllocated)
                        handle.Free();
            }
        }

        public virtual NtStatus CallLSALookupSids2(IntPtr policyHandle, LsaLookupOptions lookupOptions,
            SecurityIdentifier[] sids, out IntPtr referencedDomains, out IntPtr names)
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
                return LsaLookupSids2(policyHandle, lookupOptions, (uint) count, pSids, out referencedDomains,
                    out names);
            }
            finally
            {
                foreach (var handle in gcHandles)
                    if (handle.IsAllocated)
                        handle.Free();
            }
        }

        public virtual NtStatus CallLsaQueryInformationPolicy(IntPtr policyHandle,
            LSAPolicyInformation policyInformation, out IntPtr buffer)
        {
            return LsaQueryInformationPolicy(policyHandle, policyInformation, out buffer);
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct POLICY_ACCOUNT_DOMAIN_INFO
        {
            public LSA_UNICODE_STRING DomainName;
            public IntPtr DomainSid;
        }

        public struct OBJECT_ATTRIBUTES : IDisposable
        {
            public void Dispose()
            {
                if (objectName == IntPtr.Zero) return;
                Marshal.DestroyStructure(objectName, typeof(UNICODE_STRING));
                Marshal.FreeHGlobal(objectName);
                objectName = IntPtr.Zero;
            }

            public int len;
            public IntPtr rootDirectory;
            public uint attribs;
            public IntPtr sid;
            public IntPtr qos;
            private IntPtr objectName;
            public UNICODE_STRING ObjectName;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING : IDisposable
        {
            private readonly ushort Length;
            private readonly ushort MaximumLength;
            private IntPtr Buffer;

            public UNICODE_STRING(string s)
                : this()
            {
                if (s == null) return;
                Length = (ushort) (s.Length * 2);
                MaximumLength = (ushort) (Length + 2);
                Buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                if (Buffer == IntPtr.Zero) return;
                Marshal.FreeHGlobal(Buffer);
                Buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return (Buffer != IntPtr.Zero ? Marshal.PtrToStringUni(Buffer, Length / 2) : null) ??
                       throw new InvalidOperationException();
            }
        }

        #region SAMR Imports

        [DllImport("samlib.dll")]
        private static extern NtStatus SamCloseHandle(
            IntPtr handle
        );

        [DllImport("samlib.dll")]
        private static extern NtStatus SamFreeMemory(
            IntPtr handle
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NtStatus SamLookupDomainInSamServer(
            IntPtr serverHandle,
            ref UNICODE_STRING name,
            out IntPtr sid);

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NtStatus SamGetMembersInAlias(
            IntPtr aliasHandle,
            out IntPtr members,
            out int count);

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NtStatus SamOpenAlias(
            IntPtr domainHandle,
            AliasOpenFlags desiredAccess,
            int aliasId,
            out IntPtr aliasHandle
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NtStatus SamConnect(
            ref UNICODE_STRING serverName,
            out IntPtr serverHandle,
            SamAccessMasks desiredAccess,
            ref OBJECT_ATTRIBUTES objectAttributes
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NtStatus SamOpenDomain(
            IntPtr serverHandle,
            DomainAccessMask desiredAccess,
            [MarshalAs(UnmanagedType.LPArray)] byte[] domainSid,
            out IntPtr domainHandle
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NtStatus SamLookupIdsInDomain(IntPtr domainHandle,
            int count,
            int[] rids,
            out IntPtr names,
            out IntPtr use);

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NtStatus SamEnumerateAliasesInDomain(
            IntPtr domainHandle,
            ref int enumerationContext,
            out IntPtr buffer,
            int prefMaxLen,
            out int count);

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NtStatus SamEnumerateDomainsInSamServer(
            IntPtr serverHandle,
            ref int enumerationContext,
            out IntPtr buffer,
            int prefMaxLen,
            out int count);

        [Flags]
        [SuppressMessage("ReSharper", "UnusedMember.Local")]
        internal enum AliasOpenFlags
        {
            AddMember = 0x1,
            RemoveMember = 0x2,
            ListMembers = 0x4,
            ReadInfo = 0x8,
            WriteAccount = 0x10,
            AllAccess = 0xf001f,
            Read = 0x20004,
            Write = 0x20013,
            Execute = 0x20008
        }

        [Flags]
        [SuppressMessage("ReSharper", "UnusedMember.Local")]
        public enum DomainAccessMask
        {
            ReadPasswordParameters = 0x1,
            WritePasswordParameters = 0x2,
            ReadOtherParameters = 0x4,
            WriteOtherParameters = 0x8,
            CreateUser = 0x10,
            CreateGroup = 0x20,
            CreateAlias = 0x40,
            GetAliasMembership = 0x80,
            ListAccounts = 0x100,
            Lookup = 0x200,
            AdministerServer = 0x400,
            AllAccess = 0xf07ff,
            Read = 0x20084,
            Write = 0x2047A,
            Execute = 0x20301
        }

        [Flags]
        [SuppressMessage("ReSharper", "UnusedMember.Local")]
        internal enum SamAliasFlags
        {
            AddMembers = 0x1,
            RemoveMembers = 0x2,
            ListMembers = 0x4,
            ReadInfo = 0x8,
            WriteAccount = 0x10,
            AllAccess = 0xf001f,
            Read = 0x20004,
            Write = 0x20013,
            Execute = 0x20008
        }

        [Flags]
        [SuppressMessage("ReSharper", "UnusedMember.Local")]
        public enum SamAccessMasks
        {
            SamServerConnect = 0x1,
            SamServerShutdown = 0x2,
            SamServerInitialize = 0x4,
            SamServerCreateDomains = 0x8,
            SamServerEnumerateDomains = 0x10,
            SamServerLookupDomain = 0x20,
            SamServerAllAccess = 0xf003f,
            SamServerRead = 0x20010,
            SamServerWrite = 0x2000e,
            SamServerExecute = 0x20021
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SamRidEnumeration
        {
            internal static readonly int SizeOf = Marshal.SizeOf<SamRidEnumeration>();
            public int Rid;
            public UNICODE_STRING Name;
        }

        public enum SidNameUse
        {
            User = 1,
            Group,
            Domain,
            Alias,
            WellKnownGroup,
            DeletedAccount,
            Invalid,
            Unknown,
            Computer,
            Label,
            LogonSession
        }

        #endregion

        #region Session Enum Imports

        [DllImport("NetAPI32.dll", SetLastError = true)]
        private static extern NERR NetSessionEnum(
            [MarshalAs(UnmanagedType.LPWStr)] string ServerName,
            [MarshalAs(UnmanagedType.LPWStr)] string UncClientName,
            [MarshalAs(UnmanagedType.LPWStr)] string UserName,
            int Level,
            out IntPtr bufptr,
            int prefmaxlen,
            out int entriesread,
            out int totalentries,
            ref int resume_handle);

        [StructLayout(LayoutKind.Sequential)]
        public struct SESSION_INFO_10
        {
            [MarshalAs(UnmanagedType.LPWStr)] public string sesi10_cname;
            [MarshalAs(UnmanagedType.LPWStr)] public string sesi10_username;
            public uint sesi10_time;
            public uint sesi10_idle_time;
        }

        public enum NERR
        {
            NERR_Success = 0,
            ERROR_MORE_DATA = 234,
            ERROR_NO_BROWSER_SERVERS_FOUND = 6118,
            ERROR_INVALID_LEVEL = 124,
            ERROR_ACCESS_DENIED = 5,
            ERROR_INVALID_PARAMETER = 87,
            ERROR_NOT_ENOUGH_MEMORY = 8,
            ERROR_NETWORK_BUSY = 54,
            ERROR_BAD_NETPATH = 53,
            ERROR_NO_NETWORK = 1222,
            ERROR_INVALID_HANDLE_STATE = 1609,
            ERROR_EXTENDED_ERROR = 1208,
            NERR_BASE = 2100,
            NERR_UnknownDevDir = NERR_BASE + 16,
            NERR_DuplicateShare = NERR_BASE + 18,
            NERR_BufTooSmall = NERR_BASE + 23
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WKSTA_USER_INFO_1
        {
            public string wkui1_username;
            public string wkui1_logon_domain;
            public string wkui1_oth_domains;
            public string wkui1_logon_server;
        }

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern NERR NetWkstaUserEnum(
            string servername,
            int level,
            out IntPtr bufptr,
            int prefmaxlen,
            out int entriesread,
            out int totalentries,
            ref int resume_handle);

        [DllImport("netapi32.dll")]
        private static extern int NetApiBufferFree(
            IntPtr Buff);

        #endregion

        #region NetAPI PInvoke Calls

        [DllImport("netapi32.dll", SetLastError = true)]
        private static extern NERR NetWkstaGetInfo(
            [MarshalAs(UnmanagedType.LPWStr)] string serverName,
            uint level,
            out IntPtr bufPtr);

        public struct WorkstationInfo100
        {
            public int platform_id;
            [MarshalAs(UnmanagedType.LPWStr)] public string computer_name;
            [MarshalAs(UnmanagedType.LPWStr)] public string lan_group;
            public int ver_major;
            public int ver_minor;
        }

        #endregion

        #region DSGetDcName Imports

        [DllImport("Netapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern int DsGetDcName
        (
            [MarshalAs(UnmanagedType.LPTStr)] string ComputerName,
            [MarshalAs(UnmanagedType.LPTStr)] string DomainName,
            [In] GuidClass DomainGuid,
            [MarshalAs(UnmanagedType.LPTStr)] string SiteName,
            uint Flags,
            out IntPtr pDOMAIN_CONTROLLER_INFO
        );

        [StructLayout(LayoutKind.Sequential)]
        public class GuidClass
        {
            public Guid TheGuid;
        }

        [Flags]
        public enum DSGETDCNAME_FLAGS : uint
        {
            DS_FORCE_REDISCOVERY = 0x00000001,
            DS_DIRECTORY_SERVICE_REQUIRED = 0x00000010,
            DS_DIRECTORY_SERVICE_PREFERRED = 0x00000020,
            DS_GC_SERVER_REQUIRED = 0x00000040,
            DS_PDC_REQUIRED = 0x00000080,
            DS_BACKGROUND_ONLY = 0x00000100,
            DS_IP_REQUIRED = 0x00000200,
            DS_KDC_REQUIRED = 0x00000400,
            DS_TIMESERV_REQUIRED = 0x00000800,
            DS_WRITABLE_REQUIRED = 0x00001000,
            DS_GOOD_TIMESERV_PREFERRED = 0x00002000,
            DS_AVOID_SELF = 0x00004000,
            DS_ONLY_LDAP_NEEDED = 0x00008000,
            DS_IS_FLAT_NAME = 0x00010000,
            DS_IS_DNS_NAME = 0x00020000,
            DS_RETURN_DNS_NAME = 0x40000000,
            DS_RETURN_FLAT_NAME = 0x80000000
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct DOMAIN_CONTROLLER_INFO
        {
            [MarshalAs(UnmanagedType.LPTStr)] public string DomainControllerName;
            [MarshalAs(UnmanagedType.LPTStr)] public string DomainControllerAddress;
            public uint DomainControllerAddressType;
            public Guid DomainGuid;
            [MarshalAs(UnmanagedType.LPTStr)] public string DomainName;
            [MarshalAs(UnmanagedType.LPTStr)] public string DnsForestName;
            public uint Flags;
            [MarshalAs(UnmanagedType.LPTStr)] public string DcSiteName;
            [MarshalAs(UnmanagedType.LPTStr)] public string ClientSiteName;
        }

        #endregion

        #region LSA Imports

        [DllImport("advapi32.dll")]
        private static extern NtStatus LsaOpenPolicy(
            ref LSA_UNICODE_STRING server,
            ref LSA_OBJECT_ATTRIBUTES objectAttributes,
            LsaOpenMask desiredAccess,
            out IntPtr policyHandle
        );

        [DllImport("advapi32.dll")]
        private static extern NtStatus LsaEnumerateAccountRights(
            IntPtr policyHandle,
            IntPtr accountSid,
            IntPtr accountRights,
            out int count);

        [DllImport("advapi32.dll")]
        private static extern NtStatus LsaLookupSids(
            IntPtr policyHandle,
            uint count,
            [MarshalAs(UnmanagedType.LPArray)] IntPtr[] sidArray,
            out IntPtr referencedDomains,
            out IntPtr names
        );

        [DllImport("advapi32.dll")]
        private static extern NtStatus LsaLookupSids2(
            IntPtr policyHandle,
            LsaLookupOptions lookupOptions,
            uint count,
            [MarshalAs(UnmanagedType.LPArray)] IntPtr[] sidArray,
            out IntPtr referencedDomains,
            out IntPtr names
        );

        [DllImport("advapi32.dll")]
        private static extern NtStatus LsaQueryInformationPolicy(
            IntPtr policyHandle, LSAPolicyInformation policyInformation, out IntPtr buffer);

        [DllImport("advapi32.dll")]
        private static extern NtStatus LsaClose(
            IntPtr buffer
        );

        [DllImport("advapi32.dll")]
        public static extern NtStatus LsaFreeMemory(
            IntPtr buffer
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        [SuppressUnmanagedCodeSecurity]
        public static extern NtStatus LsaEnumerateAccountsWithUserRight(
            IntPtr PolicyHandle,
            LSA_UNICODE_STRING[] UserRights,
            out IntPtr EnumerationBuffer,
            out int CountReturned
        );

        [Flags]
        public enum LsaLookupOptions : uint
        {
            ReturnLocalNames = 0,
            PreferInternetNames = 0x40000000,
            DisallowsConnectedAccountInternetSid = 0x80000000
        }

        [Flags]
        public enum LSAPolicyInformation
        {
            PolicyAuditLogInformation = 1,
            PolicyAuditEventsInformation,
            PolicyPrimaryDomainInformation,
            PolicyPdAccountInformation,
            PolicyAccountDomainInformation,
            PolicyLsaServerRoleInformation,
            PolicyReplicaSourceInformation,
            PolicyDefaultQuotaInformation,
            PolicyModificationInformation,
            PolicyAuditFullSetInformation,
            PolicyAuditFullQueryInformation,
            PolicyDnsDomainInformation
        }

        [Flags]
        [SuppressMessage("ReSharper", "UnusedMember.Local")]
        public enum LsaOpenMask
        {
            ViewLocalInfo = 0x1,
            ViewAuditInfo = 0x2,
            GetPrivateInfo = 0x4,
            TrustAdmin = 0x8,
            CreateAccount = 0x10,
            CreateSecret = 0x20,
            CreatePrivilege = 0x40,
            SetDefaultQuotaLimits = 0x80,
            SetAuditRequirements = 0x100,
            AuditLogAdmin = 0x200,
            ServerAdmin = 0x400,
            LookupNames = 0x800,
            Notification = 0x1000,
            POLICY_READ = 0x20006,
            POLICY_ALL_ACCESS = 0x00F0FFF,
            POLICY_EXECUTE = 0X20801,
            POLICY_WRITE = 0X207F8
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_UNICODE_STRING : IDisposable
        {
            private readonly ushort Length;
            private readonly ushort MaximumLength;
            private IntPtr Buffer;

            public LSA_UNICODE_STRING(string s)
                : this()
            {
                if (s == null) return;
                Length = (ushort) (s.Length * 2);
                MaximumLength = (ushort) (Length + 2);
                Buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                if (Buffer == IntPtr.Zero) return;
                Marshal.FreeHGlobal(Buffer);
                Buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return (Buffer != IntPtr.Zero ? Marshal.PtrToStringUni(Buffer, Length / 2) : null) ??
                       throw new InvalidOperationException();
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public int Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;

            public void Dispose()
            {
                if (ObjectName == IntPtr.Zero) return;
                Marshal.DestroyStructure(ObjectName, typeof(LSA_UNICODE_STRING));
                Marshal.FreeHGlobal(ObjectName);
                ObjectName = IntPtr.Zero;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LSATranslatedNames
        {
            public SidNameUse Use;
            public LSA_UNICODE_STRING Name;
            public int DomainIndex;
        }

        public class SidPointer
        {
            private readonly byte[] data;

            public SidPointer(SecurityIdentifier identifier)
            {
                data = new byte[identifier.BinaryLength];
                identifier.GetBinaryForm(data, 0);
            }
        }

        #endregion
    }
}