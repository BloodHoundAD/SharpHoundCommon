using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using SharpHoundRPC.Handles;

namespace SharpHoundRPC.NetAPINative
{
    public static class NetAPIMethods
    {
        private const int NetWkstaUserEnumQueryLevel = 1;
        private const int NetSessionEnumLevel = 10;
        private const int NetWkstaGetInfoQueryLevel = 100;

        [DllImport("netapi32.dll")]
        internal static extern NetAPIEnums.NetAPIStatus NetApiBufferFree(
            IntPtr buffer);

        public static NetAPIResult<IEnumerable<NetWkstaUserEnumResults>> NetWkstaUserEnum(string computerName)
        {
            var resumeHandle = 0;
            var result = NetWkstaUserEnum(computerName, NetWkstaUserEnumQueryLevel, out var buffer, -1,
                out var entriesRead, out _, ref resumeHandle);

            if (result != NetAPIEnums.NetAPIStatus.Success && result != NetAPIEnums.NetAPIStatus.ErrorMoreData)
                return result;

            return NetAPIResult<IEnumerable<NetWkstaUserEnumResults>>.Ok(buffer
                .GetEnumerable<NetAPIStructs.WkstaUserInfo1>(entriesRead)
                .Select(x => new NetWkstaUserEnumResults(x.Username, x.LogonDomain)));
        }

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern NetAPIEnums.NetAPIStatus NetWkstaUserEnum(
            string servername,
            int level,
            out NetAPIPointer buffer,
            int preferredMaxLength,
            out int entriesRead,
            out int totalEntries,
            ref int resumeHandle);

        public static NetAPIResult<IEnumerable<NetSessionEnumResults>> NetSessionEnum(string computerName)
        {
            var resumeHandle = 0;
            var result = NetSessionEnum(computerName, null, null, NetSessionEnumLevel, out var buffer, -1,
                out var entriesRead, out _, ref resumeHandle);
            
            if (result != NetAPIEnums.NetAPIStatus.Success && result != NetAPIEnums.NetAPIStatus.ErrorMoreData)
                return result;

            return NetAPIResult<IEnumerable<NetSessionEnumResults>>.Ok(buffer
                .GetEnumerable<NetAPIStructs.SessionInfo10>(entriesRead)
                .Select(x => new NetSessionEnumResults(x.Username, x.CName)));
        }

        [DllImport("NetAPI32.dll", SetLastError = true)]
        private static extern NetAPIEnums.NetAPIStatus NetSessionEnum(
            [MarshalAs(UnmanagedType.LPWStr)] string serverName,
            [MarshalAs(UnmanagedType.LPWStr)] string uncClientName,
            [MarshalAs(UnmanagedType.LPWStr)] string userName,
            int level,
            out NetAPIPointer buffer,
            int preferredMaxLength,
            out int entriesRead,
            out int totalEntries,
            ref int resumeHandle);

        public static NetAPIResult<NetAPIStructs.WorkstationInfo100> NetWkstaGetInfo(string computerName)
        {
            var result = NetWkstaGetInfo(computerName, NetWkstaGetInfoQueryLevel, out var buffer);

            if (result != NetAPIEnums.NetAPIStatus.Success) return result;

            return buffer.GetData<NetAPIStructs.WorkstationInfo100>();
        }

        [DllImport("netapi32.dll", SetLastError = true)]
        private static extern NetAPIEnums.NetAPIStatus NetWkstaGetInfo(
            [MarshalAs(UnmanagedType.LPWStr)] string serverName,
            uint level,
            out NetAPIPointer bufPtr);

        public static NetAPIResult<NetAPIStructs.DomainControllerInfo> DsGetDcName(string computerName,
            string domainName)
        {
            var result = DsGetDcName(computerName, domainName, null, null,
                (uint) (NetAPIEnums.DSGETDCNAME_FLAGS.DS_IS_FLAT_NAME |
                        NetAPIEnums.DSGETDCNAME_FLAGS.DS_RETURN_DNS_NAME), out var buffer);
            if (result != NetAPIEnums.NetAPIStatus.Success) return result;

            return buffer.GetData<NetAPIStructs.DomainControllerInfo>();
        }

        [DllImport("Netapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern NetAPIEnums.NetAPIStatus DsGetDcName
        (
            [MarshalAs(UnmanagedType.LPTStr)] string computerName,
            [MarshalAs(UnmanagedType.LPTStr)] string domainName,
            [In] NetAPIStructs.GuidClass domainGuid,
            [MarshalAs(UnmanagedType.LPTStr)] string siteName,
            uint flags,
            out NetAPIPointer pDomainControllerInfo
        );
    }
}