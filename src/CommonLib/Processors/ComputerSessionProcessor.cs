using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Threading.Tasks;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib.Processors
{
    public class ComputerSessionProcessor
    {
        private readonly string _currentUserName;
        private readonly NativeMethods _nativeMethods;
        private readonly ILDAPUtils _utils;

        public ComputerSessionProcessor(ILDAPUtils utils, string currentUserName = null,
            NativeMethods nativeMethods = null)
        {
            _utils = utils;
            _nativeMethods = nativeMethods ?? new NativeMethods();
            _currentUserName = currentUserName ?? WindowsIdentity.GetCurrent().Name.Split('\\')[1];
            ;
        }

        /// <summary>
        ///     Uses the NetSessionEnum Win32 API call to get network sessions from a remote computer.
        ///     These are usually from SMB share accesses or other network sessions of the sort
        /// </summary>
        /// <param name="computerName"></param>
        /// <param name="computerSid"></param>
        /// <param name="computerDomain"></param>
        /// <returns></returns>
        public async Task<SessionAPIResult> ReadUserSessions(string computerName, string computerSid,
            string computerDomain)
        {
            var ret = new SessionAPIResult();
            NativeMethods.SESSION_INFO_10[] apiResult;

            try
            {
                apiResult = _nativeMethods.CallNetSessionEnum(computerName).ToArray();
            }
            catch (APIException e)
            {
                ret.Collected = false;
                ret.FailureReason = e.Status;
                return ret;
            }

            ret.Collected = true;
            var results = new List<Session>();

            foreach (var sesInfo in apiResult)
            {
                var username = sesInfo.sesi10_username;
                var computerSessionName = sesInfo.sesi10_cname;

                Logging.Trace($"NetSessionEnum Entry: {username}@{computerSessionName}");

                //Filter out blank/null cnames/usernames
                if (string.IsNullOrWhiteSpace(computerSessionName) || string.IsNullOrWhiteSpace(username))
                    continue;

                //Filter out blank usernames, computer accounts, the user we're doing enumeration with, and anonymous logons
                if (username.EndsWith("$") ||
                    username.Equals(_currentUserName, StringComparison.CurrentCultureIgnoreCase) ||
                    username.Equals("anonymous logon", StringComparison.CurrentCultureIgnoreCase))
                    continue;

                // Remove leading slashes for unc paths
                computerSessionName = computerSessionName.TrimStart('\\');

                string resolvedComputerSID = null;

                //Resolve "localhost" equivalents to the computer sid
                if (computerSessionName is "[::1]" or "127.0.0.1")
                    resolvedComputerSID = computerSid;
                else
                    //Attempt to resolve the host name to a SID
                    resolvedComputerSID = await _utils.ResolveHostToSid(computerSessionName, computerDomain);

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

        /// <summary>
        ///     Uses the privileged win32 API, NetWkstaUserEnum, to return the logged on users on a remote computer.
        ///     Requires administrator rights on the target system
        /// </summary>
        /// <param name="computerName"></param>
        /// <param name="computerSamAccountName"></param>
        /// <param name="computerSid"></param>
        /// <returns></returns>
        public async Task<SessionAPIResult> ReadUserSessionsPrivileged(string computerName,
            string computerSamAccountName, string computerSid)
        {
            var ret = new SessionAPIResult();
            NativeMethods.WKSTA_USER_INFO_1[] apiResult;

            try
            {
                apiResult = _nativeMethods.CallNetWkstaUserEnum(computerName).ToArray();
            }
            catch (APIException e)
            {
                ret.Collected = false;
                ret.FailureReason = e.Status;
                return ret;
            }

            ret.Collected = true;

            var results = new List<TypedPrincipal>();
            foreach (var wkstaUserInfo in apiResult)
            {
                var domain = wkstaUserInfo.wkui1_logon_domain;
                var username = wkstaUserInfo.wkui1_username;

                Logging.Trace($"NetWkstaUserEnum entry: {username}@{domain}");

                //These are local computer accounts.
                if (domain.Equals(computerSamAccountName, StringComparison.CurrentCultureIgnoreCase))
                    continue;

                //Filter out empty usernames and computer sessions
                if (string.IsNullOrWhiteSpace(username) || username.EndsWith("$", StringComparison.Ordinal))
                    continue;

                //If we dont have a domain, ignore this object
                if (string.IsNullOrWhiteSpace(domain))
                    continue;

                //Any domain with a space is unusable. It'll be things like NT Authority or Font Driver
                if (domain.Contains(" "))
                    continue;

                var res = await _utils.ResolveAccountName(username, domain);
                if (res == null)
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
    }
}