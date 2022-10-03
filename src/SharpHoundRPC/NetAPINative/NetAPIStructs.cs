using System;
using System.Runtime.InteropServices;

namespace SharpHoundRPC.NetAPINative
{
    public class NetAPIStructs
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WkstaUserInfo1
        {
            public string Username;
            public string LogonDomain;
            public string OtherDomains;
            public string LogonServer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SessionInfo10
        {
            [MarshalAs(UnmanagedType.LPWStr)] public string CName;
            [MarshalAs(UnmanagedType.LPWStr)] public string Username;
            public uint Time;
            public uint IdleTIme;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WorkstationInfo100
        {
            public int PlatformId;
            [MarshalAs(UnmanagedType.LPWStr)] public string ComputerName;
            [MarshalAs(UnmanagedType.LPWStr)] public string LanGroup;
            public int MajorVersion;
            public int MinorVersion;
        }

        [StructLayout(LayoutKind.Sequential)]
        public class GuidClass
        {
            public Guid TheGuid;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct DomainControllerInfo
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
    }
}