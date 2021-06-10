using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib.Processors
{
    public class ComputerSessionProcessor
    {
        private const int NetWkstaUserEnumQueryLevel = 1;
        private const int NetSessionEnumLevel = 10;
        private readonly ILDAPUtils _utils;

        public ComputerSessionProcessor(ILDAPUtils utils)
        {
            _utils = utils;
        }

        /// <summary>
        /// Uses the NetSessionEnum Win32 API call to get network sessions from a remote computer.
        /// These are usually from SMB share accesses or other network sessions of the sort
        /// </summary>
        /// <param name="computerName"></param>
        /// <param name="computerSid"></param>
        /// <param name="computerDomain"></param>
        /// <param name="currentUserName"></param>
        /// <returns></returns>
        public async Task<SessionAPIResult> ReadUserSessions(string computerName, string computerSid, string computerDomain, string currentUserName)
        {
            var ptr = IntPtr.Zero;
            var ret = new SessionAPIResult();

            try
            {
                var resumeHandle = IntPtr.Zero;

                Logging.Trace($"Beginning NetSessionEnum for {computerName}");
                var result = NativeMethods.NetSessionEnum(computerName, null, null, NetSessionEnumLevel, out ptr, -1,
                    out var entriesRead, out _, ref resumeHandle);
                
                Logging.Trace($"Result of NetSessionEnum for {computerName} is {result}");

                if (result != NativeMethods.NERR.NERR_Success)
                {
                    ret.FailureReason = result.ToString();
                    return ret;
                }

                ret.Collected = true;

                var results = new List<Session>();
                var iter = ptr;
                Logging.Trace($"NetSessionEnum for {computerName} returned {entriesRead} entries");
                for (var i = 0; i < entriesRead; i++)
                {
                    var data = Marshal.PtrToStructure<NativeMethods.SESSION_INFO_10>(iter);
                    iter = (IntPtr)(iter.ToInt64() + Marshal.SizeOf(typeof(NativeMethods.SESSION_INFO_10)));

                    var username = data.sesi10_username;
                    var computerSessionName = data.sesi10_cname;
                    
                    Logging.Trace($"NetSessionEnum Entry: {username}@{computerSessionName}");
                    
                    //Filter out blank/null cnames/usernames
                    if (string.IsNullOrWhiteSpace(computerSessionName) || string.IsNullOrWhiteSpace(username))
                        continue;

                    //Filter out blank usernames, computer accounts, the user we're doing enumeration with, and anonymous logons
                    if (username.EndsWith("$") ||
                        username.Equals(currentUserName, StringComparison.CurrentCultureIgnoreCase) ||
                        username.Equals("anonymous logon", StringComparison.CurrentCultureIgnoreCase))
                        continue;
                    
                    // Remove leading slashes for unc paths
                    computerSessionName = computerSessionName.TrimStart('\\');

                    string resolvedComputerSID = null;
                    
                    //Resolve "localhost" equivalents to the computer sid
                    if (computerSessionName is "[::1]" or "127.0.0.1")
                        resolvedComputerSID = computerSid;
                    else
                    {
                        //Attempt to resolve the host name to a SID
                        resolvedComputerSID = await _utils.ResolveHostToSid(computerSessionName, computerDomain);
                    }
                    
                    //Throw out this data if we couldn't resolve it successfully. 
                    if (resolvedComputerSID == null || !resolvedComputerSID.StartsWith("S-1"))
                        continue;

                    var matches = _utils.GetUserGlobalCatalogMatches(username);
                    if (matches.Length > 0)
                    {
                        results.AddRange(matches.Select(s => new Session {ComputerSID = resolvedComputerSID, UserSID = s}));
                    }
                    else
                    {
                        var res = await _utils.ResolveAccountName(username, computerDomain);
                        if (res != null)
                            results.Add(new Session
                            {
                                ComputerSID = resolvedComputerSID,
                                UserSID = res.ObjectIdentifier
                            });
                    }
                }

                ret.Results = results.ToArray();

                return ret;
            }
            finally
            {
                if (ptr != IntPtr.Zero)
                    NativeMethods.NetApiBufferFree(ptr);
            }
        }
        
        /// <summary>
        /// Uses the privileged win32 API, NetWkstaUserEnum, to return the logged on users on a remote computer.
        /// Requires administrator rights on the target system
        /// </summary>
        /// <param name="computerName"></param>
        /// <param name="computerSamAccountName"></param>
        /// <param name="computerDomain"></param>
        /// <returns></returns>
        public async Task<SessionAPIResult> ReadUserSessionsPrivileged(string computerName, string computerSamAccountName, string computerDomain, string computerSid)
        {
            var ptr = IntPtr.Zero;
            try
            {
                var ret = new SessionAPIResult();
                var resumeHandle = 0;
                
                Logging.Trace($"Beginning NetWkstaUserEnum for {computerName}");
                var result = NativeMethods.NetWkstaUserEnum(computerName, NetWkstaUserEnumQueryLevel, out ptr, -1, out var entriesRead,
                    out _, ref resumeHandle);

                Logging.Trace($"Result of NetWkstaUserEnum for computer {computerName} is {result}");
                if (result != NativeMethods.NERR.NERR_Success && result != NativeMethods.NERR.ERROR_MORE_DATA)
                {
                    ret.FailureReason = result.ToString();
                    return ret;
                }

                ret.Collected = true;

                if (!Cache.GetMachineSid(computerSid, out var machineSid))
                {
                    try
                    {
                        using var server = new SAMRPCServer(computerName, computerSamAccountName, computerSid, _utils);
                        machineSid = server.GetMachineSid();
                    }
                    catch
                    {
                        return null;
                    }
                }

                var results = new List<TypedPrincipal>();
                Logging.Trace($"NetWkstaUserEnum returned {entriesRead} entries for {computerName}");
                var iter = ptr;
                for (var i = 0; i < entriesRead; i++)
                {
                    var data = Marshal.PtrToStructure<NativeMethods.WKSTA_USER_INFO_1>(iter);
                    iter = (IntPtr)(iter.ToInt64() + Marshal.SizeOf(typeof(NativeMethods.WKSTA_USER_INFO_1)));

                    var domain = data.wkui1_logon_domain;
                    var username = data.wkui1_username;
                    
                    Logging.Trace($"NetWkstaUserEnum entry: {username}@{domain}");

                    //These are local computer accounts.
                    if (domain.Equals(computerSamAccountName, StringComparison.CurrentCultureIgnoreCase))
                        continue;
                    
                    //Filter out empty usernames and computer sessions
                    if (username.Trim() == "" || username.EndsWith("$", StringComparison.Ordinal))
                        continue;

                    //Any domain with a space is unusable. It'll be things like NT Authority or Font Driver
                    if (domain.Contains(" "))
                        continue;
                    
                    var res = await _utils.ResolveAccountName(username, computerDomain);
                    if (res == null)
                        continue;
                    
                    if (res.ObjectIdentifier.StartsWith(machineSid, StringComparison.OrdinalIgnoreCase))
                        continue;
                
                    results.Add(res);
                }

                ret.Results = results.Select(x => new Session
                {
                    ComputerSID = computerSid,
                    UserSID = x.ObjectIdentifier
                }).ToArray();

                return ret;
            }
            finally
            {
                if (ptr != IntPtr.Zero) NativeMethods.NetApiBufferFree(ptr);
            }
        }
    }
}