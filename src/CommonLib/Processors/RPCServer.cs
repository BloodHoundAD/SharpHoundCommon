using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib.Processors
{
    public class RPCServer : IDisposable
    {
        private static readonly Lazy<byte[]> WellKnownSidBytes = new(() =>
        {
            var sid = new SecurityIdentifier("S-1-5-32");
            var sidBytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(sidBytes, 0);
            return sidBytes;
        }, LazyThreadSafetyMode.PublicationOnly);

        private readonly string _computerDomain;

        private readonly string _computerName;
        private readonly string _computerSAMAccountName;
        private readonly SecurityIdentifier _computerSID;

        // Map domain sid to domain, and use AccountDomainSid to retrieve this
        private readonly ConcurrentDictionary<string, IntPtr> _domainHandles = new();
        private readonly ConcurrentDictionary<string, string> _sidToDomainCache = new();
        private string _cachedMachineSid;
        private readonly ConcurrentDictionary<string, Label> _typeCache = new();

        private readonly string[] _filteredSids =
        {
            "S-1-5-2", "S-1-5-2", "S-1-5-3", "S-1-5-4", "S-1-5-6", "S-1-5-7", "S-1-2", "S-1-2-0", "S-1-5-18",
            "S-1-5-19", "S-1-5-20"
        };

        private const string DummyMachineSid = "DUMMYSTRING";

        private readonly ILogger _log;

        private readonly NativeMethods _nativeMethods;
        private NativeMethods.OBJECT_ATTRIBUTES _obj;
        private NativeMethods.LSA_OBJECT_ATTRIBUTES _lsaObj;
        private readonly ILDAPUtils _utils;
        private IntPtr _samServerHandle;
        private IntPtr _lsaPolicyHandle;

        private bool _lsaServerOpen = false;
        private bool _samServerOpen = false;

        /// <summary>
        ///     Creates an instance of an RPCServer which is used for making SharpHound specific SAMRPC/LSA API calls for computers.
        ///     OpenSAMServer should be called before any other operations
        /// </summary>
        /// <param name="computerName">The name of the computer to connect too. This should be the network name of the computer</param>
        /// <param name="samAccountName">The samaccountname of the computer</param>
        /// <param name="computerSid">The security identifier for the computer</param>
        /// <param name="computerDomain">The domain of the computer</param>
        /// <param name="utils">LDAPUtils instance</param>
        /// <param name="methods">NativeMethods instance</param>
        /// <param name="log">ILogger instance</param>
        public RPCServer(string computerName, string samAccountName, string computerSid, string computerDomain,
            ILDAPUtils utils = null,
            NativeMethods methods = null, ILogger log = null)
        {
            //Remove the trailing '$' from the SAMAccountName
            _computerSAMAccountName = samAccountName.Remove(samAccountName.Length - 1, 1);
            _computerSID = new SecurityIdentifier(computerSid);
            _computerName = computerName;
            _computerDomain = computerDomain;
            _utils = utils;
            _nativeMethods = methods ?? new NativeMethods();
            _utils = utils ?? new LDAPUtils();
            _log = log ?? Logging.LogProvider.CreateLogger("RPCServer");
        }

        /// <summary>
        /// Opens the SAMRPC server for further use. This needs to be called before any other operations.
        /// Refer to https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/87bacbd0-7b8b-429f-abc6-4b3d895d4e90 for access masks 
        /// </summary>
        /// <param name="requestedConnectAccess"></param>
        /// <param name="requestedDomainAccess"></param>
        /// <exception cref="APIException">
        ///     An exception indicates that we failed to open a connection, as well as the reason
        /// </exception>
        public void OpenSAMServer(
            NativeMethods.SamAccessMasks requestedConnectAccess = NativeMethods.SamAccessMasks.SamServerConnect |
                                                                  NativeMethods.SamAccessMasks
                                                                      .SamServerEnumerateDomains |
                                                                  NativeMethods.SamAccessMasks.SamServerLookupDomain)
        {
            _log.LogTrace("Opening SAM Server for {ComputerName}", _computerName);

            var us = new NativeMethods.UNICODE_STRING(_computerName);
            //Every API call we make relies on both SamConnect
            //Make this call immediately and save the handle. If either fails, nothing else is going to work
            var status = _nativeMethods.CallSamConnect(ref us, out _samServerHandle,
                requestedConnectAccess,
                ref _obj);
            _log.LogTrace("SamConnect returned {Status} for {ComputerName}", status, _computerName);
            if (status != NativeMethods.NtStatus.StatusSuccess)
            {
                _nativeMethods.CallSamCloseHandle(_samServerHandle);
                throw new APIException
                {
                    Status = status.ToString(),
                    APICall = "SamConnect"
                };
            }
            //
            // status = _nativeMethods.CallSamOpenDomain(_samServerHandle, requestedDomainAccess,
            //     WellKnownSidBytes.Value, out _samDomainHandle);
            // _log.LogTrace("SamOpenDomain returned {Status} for {ComputerName}", status, _computerName);
            // if (status != NativeMethods.NtStatus.StatusSuccess)
            //     throw new APIException
            //     {
            //         Status = status.ToString(),
            //         APICall = "SamOpenDomain"
            //     };

            _samServerOpen = true;
        }

        public IEnumerable<LocalGroupAPIResult> GetGroupsAndMembers()
        {
            //First open the SAM server if it hasn't already been
            if (!_samServerOpen)
            {
                OpenSAMServer();
            }

            var groupCache = new ConcurrentBag<LocalGroupAPIResult>();

            GetMachineSid(out var machineSid);

            foreach (var domainName in ListDomainsInServer())
            {
                if (OpenDomainHandle(domainName, out var domainHandle))
                {
                    foreach (var group in GetGroupsFromDomain(domainHandle))
                    {
                        _typeCache.TryAdd(group.ObjectID, Label.LocalGroup);
                        _log.LogInformation("Got group {Group}", group.Name);
                        var result = GetLocalGroupMembers(domainHandle, group);
                        groupCache.Add(result);
                    }
                }   
            }
            // We've got all our local groups, now we need to resolve unresolved types
            var toResolve = new ConcurrentDictionary<string, List<SecurityIdentifier>>();
            foreach (var group in groupCache)
            {
                if (!group.Collected)
                    continue;
                foreach (var result in group.Results.Where(x => x.ObjectType == Label.Base))
                {
                    var sid = new SecurityIdentifier(result.ObjectIdentifier);
                    toResolve[sid.AccountDomainSid.Value].Add(sid);
                }
            }
        }

        public bool OpenDomainHandle(string domainName, out IntPtr domainHandle,
            NativeMethods.DomainAccessMask requestedDomainAccess = NativeMethods.DomainAccessMask.Lookup |
                                                                   NativeMethods.DomainAccessMask.ListAccounts)
        {
            if (_domainHandles.TryGetValue(domainName.ToUpper(), out domainHandle))
                return true;

            domainHandle = IntPtr.Zero;
            if (!LookupDomainSid(domainName, out var sid)) return false;

            var bytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(bytes, 0);
            var status =
                _nativeMethods.CallSamOpenDomain(_samServerHandle, requestedDomainAccess, bytes, out domainHandle);
            if (status != NativeMethods.NtStatus.StatusSuccess)
            {
                if (domainHandle != IntPtr.Zero)
                    _nativeMethods.CallSamFreeMemory(domainHandle);
                return false;
            }

            _domainHandles.TryAdd(domainName.ToUpper(), domainHandle);

            return true;
        }

        public bool OpenBuiltInDomain(out IntPtr domainHandle,
            NativeMethods.DomainAccessMask requestedDomainAccess = NativeMethods.DomainAccessMask.Lookup |
                                                                   NativeMethods.DomainAccessMask.ListAccounts)
        {
            if (_domainHandles.TryGetValue("BUILTIN", out domainHandle))
                return true;

            var status =
                _nativeMethods.CallSamOpenDomain(_samServerHandle, requestedDomainAccess, WellKnownSidBytes.Value,
                    out domainHandle);
            if (status != NativeMethods.NtStatus.StatusSuccess)
            {
                if (domainHandle != IntPtr.Zero)
                    _nativeMethods.CallSamFreeMemory(domainHandle);
                return false;
            }

            _domainHandles.TryAdd("BUILTIN", domainHandle);

            return true;
        }

        /// <summary>
        /// Opens the LSA policy for further use.
        /// </summary>
        /// <param name="desiredAccess"></param>
        /// <exception cref="APIException">
        /// An exception indicates a failure to open the LSA policy
        /// </exception>
        public void OpenLSAServer(
            NativeMethods.LsaOpenMask desiredAccess =
                NativeMethods.LsaOpenMask.LookupNames | NativeMethods.LsaOpenMask.ViewLocalInfo)
        {
            var us = new NativeMethods.LSA_UNICODE_STRING(_computerName);
            var status = _nativeMethods.CallLSAOpenPolicy(ref us, ref _lsaObj, desiredAccess,
                out _lsaPolicyHandle);
            _log.LogTrace($"LSAOpenPolicy returned {status} for {_computerName}");
            if (status != NativeMethods.NtStatus.StatusSuccess)
            {
                throw new APIException
                {
                    Status = status.ToString(),
                    APICall = "LSAOpenPolicy"
                };
            }

            _lsaServerOpen = true;
        }

        public void Dispose()
        {
            if (_samServerHandle != IntPtr.Zero)
            {
                _nativeMethods.CallSamCloseHandle(_samServerHandle);
                _samServerHandle = IntPtr.Zero;
            }

            if (_lsaPolicyHandle != IntPtr.Zero)
            {
                _nativeMethods.CallLSAClose(_lsaPolicyHandle);
                _lsaPolicyHandle = IntPtr.Zero;
            }

            foreach (var kv in _domainHandles)
            {
                if (kv.Value != IntPtr.Zero)
                {
                    _nativeMethods.CallSamCloseHandle(kv.Value);
                    _domainHandles[kv.Key] = IntPtr.Zero;
                }
            }

            _obj.Dispose();
            _lsaObj.Dispose();
        }

        ~RPCServer()
        {
            Dispose();
        }

        public IEnumerable<LocalGroup> GetGroupsFromDomain(IntPtr domainHandle)
        {
            if (!_samServerOpen)
            {
                _log.LogError("SAM Server is not open. Call OpenSamServer before calling GetLocalGroups");
                yield break;
            }

            if (!GetMachineSid(out var machineSid))
            {
                _log.LogError("Failed to get machine sid for {ComputerName}, cannot get local groups", _computerName);
                yield break;
            }

            var status = _nativeMethods.CallSamEnumerateAliasesInDomain(domainHandle, out var rids, out var count);
            _log.LogTrace("SamEnumerateAliasesInDomain returned {Status} on {ComputerName}", status,
                _computerName);
            if (status != NativeMethods.NtStatus.StatusSuccess || count == 0)
            {
                yield break;
            }

            for (var i = 0; i < count; i++)
            {
                var data = Marshal.PtrToStructure<NativeMethods.SamRidEnumeration>(rids +
                    (i * NativeMethods.SamRidEnumeration.SizeOf));
                _log.LogTrace("Got entry {Name} with RID {Rid}", data.Name, data.Rid);
                var group = new LocalGroup
                {
                    Name = data.Name.ToString(),
                    Rid = data.Rid,
                    ObjectID = $"{machineSid}-{data.Rid}"
                };
                yield return group;
            }
        }

        public IEnumerable<string> ListDomainsInServer()
        {
            if (!_samServerOpen)
            {
                _log.LogError("SAM Server is not open. Call OpenSamServer before calling ListDomainsInServer");
                yield break;
            }

            var domains = IntPtr.Zero;
            try
            {
                var status =
                    _nativeMethods.CallSamEnumerateDomainsInSamServer(_samServerHandle, out domains, out var count);
                _log.LogTrace("SamEnumerateDomainsInSamServer returned {Status} on {ComputerName}", status,
                    _computerName);
                if (status != NativeMethods.NtStatus.StatusSuccess || count == 0)
                {
                    throw new APIException
                    {
                        Status = status.ToString(),
                        APICall = "SamEnumerateDomainsInSamServer"
                    };
                }

                for (var i = 0; i < count; i++)
                {
                    var data = Marshal.PtrToStructure<NativeMethods.SamRidEnumeration>(domains +
                        (i * NativeMethods.SamRidEnumeration.SizeOf));
                    yield return data.Name.ToString();
                }
            }
            finally
            {
                if (domains != IntPtr.Zero)
                    _nativeMethods.CallSamFreeMemory(domains);
            }
        }
        

        /// <summary>
        ///     Reads the members in a specified local group from the open domain. The group is referenced by its RID (Relative Identifier).
        ///     Groups current used by SharpHound can be found in <cref>LocalGroupRids</cref>
        /// </summary>
        /// <param name="domainHandle"></param>
        /// <param name="groupRid"></param>
        /// <returns></returns>
        public LocalGroupAPIResult GetLocalGroupMembers(IntPtr domainHandle, LocalGroup group)
        {
            if (!_samServerOpen)
            {
                _log.LogError("SAM Server is not open. Call OpenSamServer before calling GetLocalGroupMembers");
                throw new ServerNotOpenException("SAM Server is not open");
            }

            var result = new LocalGroupAPIResult
            {
                GroupRID = group.Rid,
                ObjectId = group.ObjectID,
                Name = group.Name
            };

            var status = _nativeMethods.CallSamOpenAlias(domainHandle, NativeMethods.AliasOpenFlags.ListMembers,
                group.Rid, out var aliasHandle);
            _log.LogTrace("SamOpenAlias returned {Status} for RID {GroupRID} on {ComputerName}", status, group.Rid,
                _computerName);
            if (status != NativeMethods.NtStatus.StatusSuccess)
            {
                _nativeMethods.CallSamCloseHandle(aliasHandle);
                result.FailureReason = $"SamOpenAlias returned {status.ToString()}";
                return result;
            }

            status = _nativeMethods.CallSamGetMembersInAlias(aliasHandle, out var members, out var count);
            _log.LogTrace("SamGetMembersInAlias returned {Status} for RID {GroupRID} on {ComputerName}", status,
                group.Rid, _computerName);
            _nativeMethods.CallSamCloseHandle(aliasHandle);

            if (status != NativeMethods.NtStatus.StatusSuccess)
            {
                _nativeMethods.CallSamFreeMemory(members);
                result.FailureReason = $"SamGetMembersInAlias returned {status.ToString()}";
                return result;
            }

            _log.LogTrace("SamGetMembersInAlias returned {Count} items for RID {GroupRID} on {ComputerName}", count,
                group.Rid, _computerName);

            if (count == 0)
            {
                _nativeMethods.CallSamFreeMemory(members);
                result.Collected = true;
                return result;
            }

            var sids = new List<SecurityIdentifier>();
            for (var i = 0; i < count; i++)
                try
                {
                    var raw = Marshal.ReadIntPtr(members, Marshal.SizeOf<IntPtr>() * i);
                    var sid = new SecurityIdentifier(raw);
                    var value = sid.Value;

                    //Filter out sids we dont care about/explicitly ignore
                    if (value.StartsWith("S-1-5-80") || value.StartsWith("S-1-5-82") ||
                        value.StartsWith("S-1-5-90") || value.StartsWith("S-1-5-96")) continue;

                    if (_filteredSids.Contains(value)) continue;

                    sids.Add(sid);
                }
                catch (Exception e)
                {
                    _log.LogTrace(e, "Exception converting sid");
                }

            _nativeMethods.CallSamFreeMemory(members);

            GetMachineSid(out var machineSid);

            var converted = sids.Select(x =>
            {
                var sid = x.Value.ToUpper();
                if (!sid.StartsWith(machineSid) || sid.StartsWith(_computerSID.AccountDomainSid.Value))
                {
                    return _utils.ResolveIDAndType(sid, _computerDomain);
                }
                
                return new TypedPrincipal
                {
                    ObjectIdentifier = sid,
                    ObjectType = Label.Base
                };
            }).Where(x => x != null);

            result.Collected = true;
            result.Results = converted.ToArray();

            return result;
        }

        private Label ResolveLocalSidType(SecurityIdentifier identifier)
        {
            if (_typeCache.TryGetValue(identifier.Value, out var type))
                return type;

            var domainSid = identifier.AccountDomainSid.Value;
            var rid = identifier.Rid();

            if (_sidToDomainCache.TryGetValue(domainSid, out var domainName))
            {
                if (OpenDomainHandle(domainName, out var domainHandle))
                {
                    var ridArray = new int[1];
                    ridArray[0] = rid;
                    var status =
                        _nativeMethods.CallSamLookupIdsInDomain(domainHandle, ridArray, out var names, out var use);
                    if (status != NativeMethods.NtStatus.StatusSuccess)
                    {
                        return Label.Base;
                    }
                    
                    
                }
            }
        }

        /// <summary>
        ///     Uses API calls and caching to attempt to get the local SID of a computer.
        ///     The local SID of a computer will not match its domain SID, and is used to denote local machine accounts
        /// </summary>
        /// <returns></returns>
        public bool GetMachineSid(out string machineSid)
        {
            if (_cachedMachineSid != null)
            {
                machineSid = _cachedMachineSid;
                return machineSid != DummyMachineSid;
            }

            if (Cache.GetMachineSid(_computerSID.Value, out machineSid))
            {
                _cachedMachineSid = machineSid;
                return true;
            }

            if (LookupDomainSid(_computerSAMAccountName, out var tempSid))
            {
                machineSid = tempSid.Value;
                Cache.AddMachineSid(_computerSID.Value, tempSid.Value);
                _cachedMachineSid = tempSid.Value;
                return true;
            }

            var domain = ListDomainsInServer().DefaultIfEmpty(null).FirstOrDefault();
            if (domain != null && LookupDomainSid(domain, out tempSid))
            {
                machineSid = tempSid.Value;
                Cache.AddMachineSid(_computerSID.Value, tempSid.Value);
                _cachedMachineSid = tempSid.Value;
                return true;
            }

            machineSid = DummyMachineSid;
            _cachedMachineSid = machineSid;

            if (!OpenBuiltInDomain(out var domainHandle))
            {
                return false;
            }

            //As a fallback, try and retrieve the local administrators group and get the first account with a rid of 500
            //If at any time we encounter a failure, just return a dummy sid that wont match anything
            var status = _nativeMethods.CallSamOpenAlias(domainHandle, NativeMethods.AliasOpenFlags.ListMembers,
                (int) LocalGroupRids.Administrators, out var aliasHandle);
            _log.LogTrace("SamOpenAlias returned {Status} for Administrators on {ComputerName}", status, _computerName);
            if (status != NativeMethods.NtStatus.StatusSuccess)
            {
                _nativeMethods.CallSamCloseHandle(aliasHandle);
                return false;
            }

            status = _nativeMethods.CallSamGetMembersInAlias(aliasHandle, out var members, out var count);
            _log.LogTrace("SamGetMembersInAlias returned {Status} for Administrators on {ComputerName}", status,
                _computerName);
            if (status != NativeMethods.NtStatus.StatusSuccess)
            {
                _nativeMethods.CallSamCloseHandle(aliasHandle);
                return false;
            }

            _nativeMethods.CallSamCloseHandle(aliasHandle);

            if (count == 0)
            {
                _nativeMethods.CallSamFreeMemory(members);
                return false;
            }

            var sids = new List<string>();
            for (var i = 0; i < count; i++)
                try
                {
                    var ptr = Marshal.ReadIntPtr(members, Marshal.SizeOf<IntPtr>() * i);
                    var sid = new SecurityIdentifier(ptr).Value;
                    sids.Add(sid);
                }
                catch (Exception e)
                {
                    _log.LogDebug(e, "GetMachineSid - Exception converting sid");
                }

            _nativeMethods.CallSamFreeMemory(members);

            var domainSid = _computerSID.AccountDomainSid.Value.ToUpper();

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
                }).Where(x => x != null).DefaultIfEmpty(null)
                .FirstOrDefault(x => x.EndsWith("-500") && !x.ToUpper().StartsWith(domainSid));

            if (machineSid == null)
            {
                _log.LogTrace("Did not get a machine SID for {ComputerName}", _computerName);
                return false;
            }

            machineSid = new SecurityIdentifier(machineSid).AccountDomainSid.Value;

            Cache.AddMachineSid(_computerSID.Value, machineSid);
            _cachedMachineSid = machineSid;
            return true;
        }

        private bool LookupDomainSid(string domainName, out SecurityIdentifier sid)
        {
            var unicodeString = new NativeMethods.UNICODE_STRING(domainName);
            sid = null;
            try
            {
                var status =
                    _nativeMethods.CallSamLookupDomainInSamServer(_samServerHandle, ref unicodeString, out var ptrSid);
                _log.LogTrace("SamLookupDomainInSamServer returned {Status} on {ComputerName} for {Domain}", status,
                    _computerName, domainName);
                if (status == NativeMethods.NtStatus.StatusSuccess)
                {
                    sid = new SecurityIdentifier(ptrSid);
                    _nativeMethods.CallSamFreeMemory(ptrSid);
                    return true;
                }
                else
                {
                    return false;
                }
            }
            catch
            {
                return false;
            }
            finally
            {
                unicodeString.Dispose();
            }
        }
    }

    public class ServerNotOpenException : Exception
    {
        public ServerNotOpenException(string message) : base(message)
        {
        }
    }

    public class APIException : Exception
    {
        public string Status { get; set; }
        public string APICall { get; set; }

        public override string ToString()
        {
            return $"Call to {APICall} returned {Status}";
        }
    }

    public class LocalItem
    {
        public int RelativeID { get; set; }
        public Label ObjectType { get; set; }
        public string ObjectID { get; set; }
        public string Domain { get; set; }
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