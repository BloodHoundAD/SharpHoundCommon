using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib.Processors
{
    public class LSAServer : IDisposable
    {
        private readonly NativeMethods _nativeMethods;
        private readonly ILDAPUtils _utils;
        private readonly string _computerName;
        private readonly NativeMethods.LSA_OBJECT_ATTRIBUTES _obj;

        private readonly IntPtr _policyHandle;
        private readonly ILogger _log;
        
        /// <summary>
        /// Creates an instance of an RPCServer which is used for making SharpHound specific LSA API calls for computers
        /// </summary>
        /// <param name="computerName"></param>
        /// <param name="utils"></param>
        /// <param name="methods"></param>
        /// <exception cref="APIException"></exception>
        public LSAServer(string computerName, ILDAPUtils utils = null, NativeMethods methods = null, ILogger log = null)
        {
            _computerName = computerName;
            _nativeMethods = methods ?? new NativeMethods();
            _utils = utils ?? new LDAPUtils();
            _log = log ?? Logging.LogProvider.CreateLogger("SAMRPCServer");
            _log.LogTrace($"Opening LSA server for {computerName}");
            
            var us = new NativeMethods.LSA_UNICODE_STRING(computerName);
            var status = _nativeMethods.CallLSAOpenPolicy(ref us, ref _obj, NativeMethods.LsaOpenMask.LookupNames | NativeMethods.LsaOpenMask.ViewLocalInfo,
                out var policyHandle);
            _log.LogTrace($"LSAOpenPolicy returned {status} for {computerName}");
            if (status != NativeMethods.NtStatus.StatusSuccess)
            {
                _nativeMethods.CallLSAClose(policyHandle);

                throw new APIException
                {
                    Status = status.ToString(),
                    APICall = "LSAOpenPolicy"
                };
            }

            _policyHandle = policyHandle;
        }

        /// <summary>
        /// Reads principals granted the specified privilege. Refer to <see cref="LSAPrivileges"/> for a list of relevant privileges.
        /// </summary>
        /// <param name="privilege"></param>
        /// <returns></returns>
        public IEnumerable<string> ReadLSAPrivilege(string privilege)
        {
            var result = new LSAPrivilegeAPIResult();
            var status =
                _nativeMethods.CallLSAEnumerateAccountsWithUserRight(_policyHandle, privilege, out var accounts,
                    out var count);
            
            _log.LogTrace($"LSAEnumerateAccountsWithUserRight returned {status} for {privilege} on {_computerName}");
            if (status != NativeMethods.NtStatus.StatusSuccess)
            {
                _nativeMethods.CallLSAClose(accounts);
                result.FailureReason = $"LSAEnumerateAccountsWithUserRight returned {status}";
                yield break;
            }
            
            _log.LogTrace($"LSAEnumerateAccountsWithUserRight returned {count} objects for privilege {privilege} on {_computerName}");

            if (count == 0)
            {
                _nativeMethods.CallLSAClose(accounts);
                result.Collected = true;
                yield break;
            }

            var sids = new List<string>();
            for (var i = 0; i < count; i++)
                try
                {
                    var raw = Marshal.ReadIntPtr(accounts, Marshal.SizeOf<IntPtr>() * i);
                    var sid = new SecurityIdentifier(raw).Value;
                    sids.Add(sid);
                }
                catch (Exception e)
                {
                    _log.LogTrace($"Exception converting sid: {e}");
                }

            _nativeMethods.CallLSAClose(accounts);

            foreach (var sid in sids)
            {
                yield return sid;
            }
        }
        
        public void Dispose()
        {
            if (_policyHandle != IntPtr.Zero) _nativeMethods.CallLSAClose(_policyHandle);
            
            _obj.Dispose();
        }
    }
}