using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib.Processors
{
    public class SAMRPCServer : IDisposable
    {
        private readonly string _computerSAN;
        private readonly string _computerSID;
        
        private IntPtr _serverHandle;
        private IntPtr _domainHandle;
        private readonly NativeMethods.OBJECT_ATTRIBUTES _obj;

        private readonly string[] _filteredSids = {
            "S-1-5-2", "S-1-5-2", "S-1-5-3", "S-1-5-4", "S-1-5-6", "S-1-5-7", "S-1-2", "S-1-2-0", "S-1-5-18",
            "S-1-5-19", "S-1-5-20"
        };

        private static readonly Lazy<byte[]> WellKnownSidBytes = new(() =>
        {
            var sid = new SecurityIdentifier("S-1-5-32");
            var sidBytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(sidBytes, 0);
            return sidBytes;
        }, LazyThreadSafetyMode.PublicationOnly);

        /// <summary>
        /// Creates an instance of an RPCServer which is used for making SharpHound specific SAMRPC API calls for computers
        /// </summary>
        /// <param name="name">The name of the computer to connect too. This should be the network name of the computer</param>
        /// <param name="samAccountName">The samaccountname of the computer</param>
        /// <param name="computerSid">The security identifier for the computer</param>
        /// <exception cref="APIException">An exception if the an API fails to connect initially. Generally indicates the server is unavailable or permissions aren't available.</exception>
        public SAMRPCServer(string name, string samAccountName, string computerSid)
        {
            _computerSAN = samAccountName;
            _computerSID = computerSid;
            
            var us = new NativeMethods.UNICODE_STRING(name);
            //Every API call we make relies on both SamConnect and SamOpenDomain
            //Make these calls immediately and save the handles. If either fails, nothing else is going to work
            var status = SamConnect(ref us, out _serverHandle,
                SamAccessMasks.SamServerLookupDomain | SamAccessMasks.SamServerConnect, ref _obj);
            if (status != NativeMethods.NtStatus.StatusSuccess)
            {
                SamCloseHandle(_serverHandle);
                throw new APIException
                {
                    Status = status.ToString(),
                    APICall = "SamConnect"
                };
            }
            
            status = SamOpenDomain(_serverHandle, DomainAccessMask.Lookup, WellKnownSidBytes.Value, out _domainHandle);
            if (status != NativeMethods.NtStatus.StatusSuccess)
            {
                throw new APIException
                {
                    Status = status.ToString(),
                    APICall = "SamOpenDomain"
                };
            }
        }

        public LocalGroupAPIResult GetLocalGroupMembers(LocalGroupRids rid)
        {
            var result = new LocalGroupAPIResult();

            var status = SamOpenAlias(_domainHandle, AliasOpenFlags.ListMembers, (int) rid, out var aliasHandle);
            if (status != NativeMethods.NtStatus.StatusSuccess)
            {
                SamCloseHandle(aliasHandle);
                result.FailureReason = $"SamOpenAlias returned {status.ToString()}";
                return result;
            }

            status = SamGetMembersInAlias(aliasHandle, out var members, out var count);
            
            SamCloseHandle(aliasHandle);

            if (status != NativeMethods.NtStatus.StatusSuccess)
            {
                SamFreeMemory(members);
                result.FailureReason = $"SamGetMembersInAlias returned {status.ToString()}";
                return result;
            }
            
            Logging.Debug($"API call returned count of {count} ");

            if (count == 0)
            {
                SamFreeMemory(members);
                result.Collected = true;
                return result;
            }

            var sids = new List<string>();
            for (var i = 0; i < count; i++)
            {
                try
                {
                    var raw = Marshal.ReadIntPtr(members, Marshal.SizeOf(typeof(IntPtr)) * i);
                    var sid = new SecurityIdentifier(raw).Value;
                    sids.Add(sid);
                }
                catch (Exception e)
                {
                    Logging.Debug($"Exception converting sid: {e}");
                }
            }
            
            SamFreeMemory(members);
            
            var machineSid = GetMachineSid();
            Logging.Debug($"Resolved machine sid to {machineSid}");
            var converted = sids.Select(x =>
            {
                Logging.Debug(x);
                //Filter out machine accounts, service accounts, iis app pool accounts, window manager, font driver
                if (x.StartsWith(machineSid) || x.StartsWith("S-1-5-80") || x.StartsWith("S-1-5-82") || x.StartsWith("S-1-5-90") || x.StartsWith("S-1-5-96"))
                {
                    return null;
                }

                if (_filteredSids.Contains(x))
                {
                    return null;
                }

                var res = LDAPUtils.ResolveIDAndType(x, LDAPUtils.GetDomainNameFromSid(x));

                return res;
            }).Where(x => x != null);

            result.Collected = true;
            result.Results = converted.ToArray();

            return result;
        }

        public string GetMachineSid()
        {
            if (Cache.GetMachineSid(_computerSID, out var machineSid))
            {
                return machineSid;
            }
            
            NativeMethods.NtStatus status;
            //Try the simplest method first, getting the SID directly using samaccountname
            try
            {
                var san = new NativeMethods.UNICODE_STRING(_computerSAN);
                status = SamLookupDomainInSamServer(_serverHandle, ref san, out var temp);
                if (status == NativeMethods.NtStatus.StatusSuccess)
                {
                    machineSid = new SecurityIdentifier(temp).Value;
                    SamFreeMemory(temp);
                    Cache.AddMachineSid(_computerSID, machineSid);
                    return machineSid;
                }
            }
            catch
            {
                //pass
            }

            machineSid = "DUMMYSTRING";
            
            //As a fallback, try and retrieve the local administrators group and get the first account with a rid of 500
            //If at any time we encounter a failure, just return a dummy sid that wont match anything

            status = SamOpenAlias(_domainHandle, AliasOpenFlags.ListMembers,
                (int) LocalGroupRids.Administrators, out var aliasHandle);
            if (status != NativeMethods.NtStatus.StatusSuccess)
            {
                SamCloseHandle(aliasHandle);
                return machineSid;
            }


            status = SamGetMembersInAlias(aliasHandle, out var members, out var count);
            if (status != NativeMethods.NtStatus.StatusSuccess)
            {
                SamCloseHandle(aliasHandle);
                return machineSid;
            }

            SamCloseHandle(aliasHandle);

            if (count == 0)
            {
                SamFreeMemory(members);
                return machineSid;
            }
            
            var sids = new List<string>();
            for (var i = 0; i < count; i++)
            {
                try
                {
                    var ptr = Marshal.ReadIntPtr(members, Marshal.SizeOf(typeof(IntPtr)) * i);
                    var sid = new SecurityIdentifier(ptr).Value;
                    sids.Add(sid);
                }
                catch (Exception e)
                {
                    Logging.Debug($"Exception converting sid: {e}");
                }
            }
            
            var domainSid = new SecurityIdentifier(_computerSID).AccountDomainSid.Value.ToUpper();

            machineSid = sids.Select(x =>
            {
                try
                {
                    return new SecurityIdentifier(x).Value;
                }
                catch
                {
                    return null;
                }
            }).Where(x => x != null).DefaultIfEmpty(null).FirstOrDefault(x => x.EndsWith("-500") && !x.ToUpper().StartsWith(domainSid));

            if (machineSid == null)
            {
                return "DUMMYSTRING";
            }

            machineSid = new SecurityIdentifier(machineSid).AccountDomainSid.Value;
            
            Cache.AddMachineSid(_computerSID, machineSid);
            return machineSid;
        }
        
        public void Dispose()
        {
            if (_domainHandle != IntPtr.Zero)
            {
                SamCloseHandle(_domainHandle);
                _domainHandle = IntPtr.Zero;;
            }
            
            if (_serverHandle != IntPtr.Zero)
            {
                SamCloseHandle(_serverHandle);
                _serverHandle = IntPtr.Zero;
            }
        }

        #region SAMR Imports

        [DllImport("samlib.dll")]
        private static extern NativeMethods.NtStatus SamCloseHandle(
            IntPtr handle
        );

        [DllImport("samlib.dll")]
        private static extern NativeMethods.NtStatus SamFreeMemory(
            IntPtr handle
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NativeMethods.NtStatus SamLookupDomainInSamServer(
            IntPtr serverHandle,
            ref NativeMethods.UNICODE_STRING name,
            out IntPtr sid);

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NativeMethods.NtStatus SamGetMembersInAlias(
            IntPtr aliasHandle,
            out IntPtr members,
            out int count);

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NativeMethods.NtStatus SamOpenAlias(
            IntPtr domainHandle,
            AliasOpenFlags desiredAccess,
            int aliasId,
            out IntPtr aliasHandle
        );


        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NativeMethods.NtStatus SamConnect(
            ref NativeMethods.UNICODE_STRING serverName,
            out IntPtr serverHandle,
            SamAccessMasks desiredAccess,
            ref NativeMethods.OBJECT_ATTRIBUTES objectAttributes
            );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NativeMethods.NtStatus SamOpenDomain(
            IntPtr serverHandle,
            DomainAccessMask desiredAccess,
            [MarshalAs(UnmanagedType.LPArray)]byte[] domainSid,
            out IntPtr domainHandle
        );

        [Flags]
        [SuppressMessage("ReSharper", "UnusedMember.Local")]
        private enum AliasOpenFlags
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
        private enum LsaOpenMask
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
            Notification = 0x1000
        }

        [Flags]
        [SuppressMessage("ReSharper", "UnusedMember.Local")]
        private enum DomainAccessMask
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
        private enum SamAliasFlags
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
        private enum SamAccessMasks
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
        #endregion
    }
    
    public class APIException : Exception
    {
        internal string Status { get; set; }
        internal string APICall { get; set; }
            
        public override string ToString()
        {
            return $"Call to {APICall} returned {Status}";
        }
    }

    public enum LocalGroupRids
    {
        None = 0,
        Administrators = 544,
        RemoteDesktopUsers = 555,
        DcomUsers = 562,
        PSRemote = 580
    }
}