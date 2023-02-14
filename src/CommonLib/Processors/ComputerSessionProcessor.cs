using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Impersonate;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib.Processors
{
    public class ComputerSessionProcessor
    {
        public delegate Task ComputerStatusDelegate(CSVComputerStatus status);

        private static readonly Regex SidRegex = new(@"S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$", RegexOptions.Compiled);
        private readonly string _currentUserName;
        private readonly ILogger _log;
        private readonly NativeMethods _nativeMethods;
        private readonly ILDAPUtils _utils;
        private readonly bool _doLocalAdminSessionEnum;
        private readonly string _localAdminUsername;
        private readonly string _localAdminPassword;

        public ComputerSessionProcessor(ILDAPUtils utils, string currentUserName = null, NativeMethods nativeMethods = null, ILogger log = null, bool doLocalAdminSessionEnum = false, string localAdminUsername = null, string localAdminPassword = null)
        {
            _utils = utils;
            _nativeMethods = nativeMethods ?? new NativeMethods();
            _currentUserName = currentUserName ?? WindowsIdentity.GetCurrent().Name.Split('\\')[1];
            _log = log ?? Logging.LogProvider.CreateLogger("CompSessions");
            _doLocalAdminSessionEnum = doLocalAdminSessionEnum;
            _localAdminUsername = localAdminUsername;
            _localAdminPassword = localAdminPassword;
        }

        public event ComputerStatusDelegate ComputerStatusEvent;

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
            SharpHoundRPC.NetAPINative.NetAPIResult<IEnumerable<SharpHoundRPC.NetAPINative.NetSessionEnumResults>> result;

            if (_doLocalAdminSessionEnum)
            {
                // If we are authenticating using a local admin, we need to impersonate for this
                Impersonator Impersonate;
                using (Impersonate = new Impersonator(_localAdminUsername, ".", _localAdminPassword, LogonType.LOGON32_LOGON_NEW_CREDENTIALS, LogonProvider.LOGON32_PROVIDER_WINNT50))
                {
                    result = _nativeMethods.NetSessionEnum(computerName);
                }

                if (result.IsFailed)
                {
                    // Fall back to default User
                    _log.LogDebug("NetSessionEnum failed on {ComputerName} with local admin credentials: {Status}. Fallback to default user.", computerName, result.Status);
                    result = _nativeMethods.NetSessionEnum(computerName);
                }
            }
            else
            {
                result = _nativeMethods.NetSessionEnum(computerName);
            }

            if (result.IsFailed)
            {
                await SendComputerStatus(new CSVComputerStatus
                {
                    Status = result.Status.ToString(),
                    Task = "NetSessionEnum",
                    ComputerName = computerName
                });
                _log.LogDebug("NetSessionEnum failed on {ComputerName}: {Status}", computerName, result.Status);
                ret.Collected = false;
                ret.FailureReason = result.Status.ToString();
                return ret;
            }

            _log.LogDebug("NetSessionEnum succeeded on {ComputerName}", computerName);
            await SendComputerStatus(new CSVComputerStatus
            {
                Status = CSVComputerStatus.StatusSuccess,
                Task = "NetSessionEnum",
                ComputerName = computerName
            });

            ret.Collected = true;
            var results = new List<Session>();

            foreach (var sesInfo in result.Value)
            {
                var username = sesInfo.Username;
                var computerSessionName = sesInfo.ComputerName;

                _log.LogTrace("NetSessionEnum Entry: {Username}@{ComputerSessionName} from {ComputerName}", username,
                    computerSessionName, computerName);

                //Filter out blank/null cnames/usernames
                if (string.IsNullOrWhiteSpace(computerSessionName) || string.IsNullOrWhiteSpace(username))
                {
                    _log.LogTrace("Skipping NetSessionEnum entry with null session/user");
                    continue;
                }

                //Filter out blank usernames, computer accounts, the user we're doing enumeration with, and anonymous logons
                if (username.EndsWith("$") ||
                    username.Equals(_currentUserName, StringComparison.CurrentCultureIgnoreCase) ||
                    username.Equals("anonymous logon", StringComparison.CurrentCultureIgnoreCase))
                {
                    _log.LogTrace("Skipping NetSessionEnum entry for {Username}", username);
                    continue;
                }

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
                {
                    _log.LogTrace("Unable to resolve {ComputerSessionName} to real SID", computerSessionName);
                    continue;
                }

                var matches = _utils.GetUserGlobalCatalogMatches(username);
                if (matches.Length > 0)
                {
                    results.AddRange(
                        matches.Select(s => new Session {ComputerSID = resolvedComputerSID, UserSID = s}));
                }
                else
                {
                    var res = _utils.ResolveAccountName(username, computerDomain);
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
            SharpHoundRPC.NetAPINative.NetAPIResult<IEnumerable<SharpHoundRPC.NetAPINative.NetWkstaUserEnumResults>> result;

            if (_doLocalAdminSessionEnum)
            {
                // If we are authenticating using a local admin, we need to impersonate for this
                Impersonator Impersonate;
                using (Impersonate = new Impersonator(_localAdminUsername, ".", _localAdminPassword, LogonType.LOGON32_LOGON_NEW_CREDENTIALS, LogonProvider.LOGON32_PROVIDER_WINNT50))
                {
                    result = _nativeMethods.NetWkstaUserEnum(computerName);
                }

                if (result.IsFailed)
                {
                    // Fall back to default User
                    _log.LogDebug("NetWkstaUserEnum failed on {ComputerName} with local admin credentials: {Status}. Fallback to default user.", computerName, result.Status);
                    result = _nativeMethods.NetWkstaUserEnum(computerName);
                }
            }
            else
            {
                result = _nativeMethods.NetWkstaUserEnum(computerName);
            }

            if (result.IsFailed)
            {
                await SendComputerStatus(new CSVComputerStatus
                {
                    Status = result.Status.ToString(),
                    Task = "NetWkstaUserEnum",
                    ComputerName = computerName
                });
                _log.LogDebug("NetWkstaUserEnum failed on {ComputerName}: {Status}", computerName, result.Status);
                ret.Collected = false;
                ret.FailureReason = result.Status.ToString();
                return ret;
            }

            _log.LogDebug("NetWkstaUserEnum succeeded on {ComputerName}", computerName);
            await SendComputerStatus(new CSVComputerStatus
            {
                Status = result.Status.ToString(),
                Task = "NetWkstaUserEnum",
                ComputerName = computerName
            });

            ret.Collected = true;

            var results = new List<TypedPrincipal>();
            foreach (var wkstaUserInfo in result.Value)
            {
                var domain = wkstaUserInfo.LogonDomain;
                var username = wkstaUserInfo.Username;

                _log.LogTrace("NetWkstaUserEnum entry: {Username}@{Domain} from {ComputerName}", username, domain,
                    computerName);

                //These are local computer accounts.
                if (domain.Equals(computerSamAccountName, StringComparison.CurrentCultureIgnoreCase))
                {
                    _log.LogTrace("Skipping local entry {Username}@{Domain}", username, domain);
                    continue;
                }

                //Filter out empty usernames and computer sessions
                if (string.IsNullOrWhiteSpace(username) || username.EndsWith("$", StringComparison.Ordinal))
                {
                    _log.LogTrace("Skipping null or computer session");
                    continue;
                }

                //If we dont have a domain, ignore this object
                if (string.IsNullOrWhiteSpace(domain))
                {
                    _log.LogTrace("Skipping null/empty domain");
                    continue;
                }

                //Any domain with a space is unusable. It'll be things like NT Authority or Font Driver
                if (domain.Contains(" "))
                {
                    _log.LogTrace("Skipping domain with space: {Domain}", domain);
                    continue;
                }

                var res = _utils.ResolveAccountName(username, domain);
                if (res == null)
                    continue;

                _log.LogTrace("Resolved NetWkstaUserEnum entry: {SID}", res.ObjectIdentifier);
                results.Add(res);
            }

            ret.Results = results.Select(x => new Session
            {
                ComputerSID = computerSid,
                UserSID = x.ObjectIdentifier
            }).ToArray();

            return ret;
        }

        public async Task<SessionAPIResult> ReadUserSessionsRegistry(string computerName, string computerDomain,
            string computerSid)
        {
            var ret = new SessionAPIResult();

            RegistryKey key = null;

            try
            {
                var task = OpenRegistryKey(computerName, RegistryHive.Users);
                
                if (await Task.WhenAny(task, Task.Delay(10000)) != task)
                {
                    _log.LogDebug("Hit timeout on registry enum on {Server}. Abandoning registry enum", computerName);
                    ret.Collected = false;
                    ret.FailureReason = "Timeout";
                    await SendComputerStatus(new CSVComputerStatus
                    {
                        Status = "Timeout",
                        Task = "RegistrySessionEnum",
                        ComputerName = computerName
                    });
                    return ret;
                }
                
                key = task.Result;

                ret.Collected = true;
                await SendComputerStatus(new CSVComputerStatus
                {
                    Status = CSVComputerStatus.StatusSuccess,
                    Task = "RegistrySessionEnum",
                    ComputerName = computerName
                });
                _log.LogDebug("Registry session enum succeeded on {ComputerName}", computerName);
                ret.Results = key.GetSubKeyNames()
                    .Where(subkey => SidRegex.IsMatch(subkey))
                    .Select(x => _utils.ResolveIDAndType(x, computerDomain))
                    .Where(x => x != null)
                    .Select(x =>
                        new Session
                        {
                            ComputerSID = computerSid,
                            UserSID = x.ObjectIdentifier
                        })
                    .ToArray();

                return ret;
            }
            catch (Exception e)
            {
                _log.LogDebug("Registry session enum failed on {ComputerName}: {Status}", computerName, e.Message);
                await SendComputerStatus(new CSVComputerStatus
                {
                    Status = e.Message,
                    Task = "RegistrySessionEnum",
                    ComputerName = computerName
                });
                ret.Collected = false;
                ret.FailureReason = e.Message;
                return ret;
            }
            finally
            {
                key?.Dispose();
            }
        }

        private Task<RegistryKey> OpenRegistryKey(string computerName, RegistryHive hive)
        {
            return Task.Run(() => RegistryKey.OpenRemoteBaseKey(hive, computerName));
        }

        private async Task SendComputerStatus(CSVComputerStatus status)
        {
            if (ComputerStatusEvent is not null) await ComputerStatusEvent.Invoke(status);
        }
    }
}
