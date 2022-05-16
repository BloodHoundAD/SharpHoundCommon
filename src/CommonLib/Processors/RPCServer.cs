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
        private const string DummyMachineSid = "DUMMYSTRING";

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
        private readonly string _computerDomainSid;

        private readonly DomainHandleManager _domainHandleManager;

        private readonly string[] _filteredSids =
        {
            "S-1-5-2", "S-1-5-2", "S-1-5-3", "S-1-5-4", "S-1-5-6", "S-1-5-7", "S-1-2", "S-1-2-0", "S-1-5-18",
            "S-1-5-19", "S-1-5-20"
        };

        private readonly ILogger _log;

        private readonly NativeMethods _nativeMethods;
        private readonly ConcurrentDictionary<string, CachedLocalItem> _typeCache = new();
        private readonly ILDAPUtils _utils;
        private string _cachedMachineSid;
        private NativeMethods.LSA_OBJECT_ATTRIBUTES _lsaObj;
        private IntPtr _lsaPolicyHandle;

        private bool _lsaServerOpen;
        private NativeMethods.OBJECT_ATTRIBUTES _obj;
        private IntPtr _samServerHandle;
        private bool _samServerOpen;

        /// <summary>
        ///     Creates an instance of an RPCServer which is used for making SharpHound specific SAMRPC/LSA API calls for
        ///     computers.
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
            _computerDomainSid = _computerSID.AccountDomainSid.Value;
            _computerName = computerName;
            _computerDomain = computerDomain;
            _utils = utils;
            _nativeMethods = methods ?? new NativeMethods();
            _utils = utils ?? new LDAPUtils();
            _domainHandleManager = new DomainHandleManager(_nativeMethods);
            _log = log ?? Logging.LogProvider.CreateLogger("RPCServer");
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

            _domainHandleManager.Dispose();

            _obj.Dispose();
            _lsaObj.Dispose();
        }

        /// <summary>
        ///     Opens the SAMRPC server for further use. This needs to be called before any other operations.
        ///     Refer to https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/87bacbd0-7b8b-429f-abc6-4b3d895d4e90
        ///     for access masks
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

            _samServerOpen = true;
        }
        
        /// <summary>
        ///     Opens the LSA policy for further use.
        /// </summary>
        /// <param name="desiredAccess"></param>
        /// <exception cref="APIException">
        ///     An exception indicates a failure to open the LSA policy
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
                throw new APIException
                {
                    Status = status.ToString(),
                    APICall = "LSAOpenPolicy"
                };

            _lsaServerOpen = true;
        }

        public IEnumerable<UserRightsAssignmentAPIResult> GetUserRightsAssignments()
        {
            if (!_lsaServerOpen) OpenLSAServer();
            
            foreach (var privilege in LSAPrivileges.DesiredPrivileges)
            {
                var result = new UserRightsAssignmentAPIResult
                {
                    Collected = false,
                    Privilege = privilege
                };
                
                var status = _nativeMethods.CallLSAEnumerateAccountsWithUserRight(_lsaPolicyHandle, privilege,
                    out var buffer, out var count);

                if (status != NativeMethods.NtStatus.StatusSuccess)
                {
                    if (buffer != IntPtr.Zero)
                    {
                        _nativeMethods.CallLSAFreeMemory(buffer);
                    }
                    
                    result.FailureReason = $"LSAEnumerateAccountsWithUserRight returned {status}";
                    yield return result;
                }

                result.Collected = true;

                var sids = new List<SecurityIdentifier>();
                for (var i = 0; i < count; i++)
                {
                    try
                    {
                        var raw = Marshal.ReadIntPtr(buffer, Marshal.SizeOf<IntPtr>() * i);
                        var sid = new SecurityIdentifier(raw);
                        _log.LogTrace("Got sid {sid} for {ura}", sid.Value, privilege);
                        sids.Add(sid);
                    }
                    catch (Exception e)
                    {
                        _log.LogTrace(e,"Exception converting sid");
                    }
                }
                
                if (_cachedMachineSid == null && !_samServerOpen)
                {
                    OpenSAMServer();
                }

                var resolved = new List<TypedPrincipal>();
                var toResolve = new List<SecurityIdentifier>();
                foreach (var sid in sids)
                {
                    if (WellKnownPrincipal.GetWellKnownPrincipal(sid.Value, out var common))
                    {
                        common.ObjectIdentifier = $"{_computerSID}-{sid.Rid()}";
                        if (common.ObjectType == Label.User)
                        {
                            common.ObjectType = Label.LocalUser;
                        }else if (common.ObjectType == Label.Group)
                        {
                            common.ObjectType = Label.LocalGroup;
                        }
                        resolved.Add(common);
                    }else if (IsMachineAccount(sid))
                    {
                        toResolve.Add(sid);
                    }
                    else
                    {
                        var res = _utils.ResolveIDAndType(sid.Value, _computerDomain);
                        resolved.Add(res);
                    }
                }

                if (toResolve.Count == 0)
                {
                    result.Results = resolved.ToArray();
                    yield return result;
                }
                    

                var resolvedNames = new List<NamedPrincipal>();
                status = _nativeMethods.CallLSALookupSids(_lsaPolicyHandle, toResolve.ToArray(), out var domains,
                    out var names);

                if (status != NativeMethods.NtStatus.StatusSuccess && status != NativeMethods.NtStatus.StatusSomeMapped)
                {
                    _log.LogError("LSALookupSids returned {status} for {computer}, unable to resolve local sids", status, _computerName);
                    resolved.AddRange(toResolve.Select(x => new TypedPrincipal(x.Value, Label.Base)));
                    result.Results = resolved.ToArray();
                    yield return result;
                }

                for (var i = 0; i < toResolve.Count; i++)
                {
                    var translated = Marshal.PtrToStructure<NativeMethods.LSATranslatedNames>(names +
                        Marshal.SizeOf<NativeMethods.LSATranslatedNames>() * i);

                    Label objectType;
                    switch (translated.Use)
                    {
                        case NativeMethods.SidNameUse.User:
                            objectType = Label.LocalUser;
                            break;
                        case NativeMethods.SidNameUse.Group:
                            objectType = Label.LocalGroup;
                            break;
                        case NativeMethods.SidNameUse.Alias:
                            objectType = Label.LocalGroup;
                            break;
                        case NativeMethods.SidNameUse.Domain:
                        case NativeMethods.SidNameUse.WellKnownGroup:
                        case NativeMethods.SidNameUse.DeletedAccount:
                        case NativeMethods.SidNameUse.Invalid:
                        case NativeMethods.SidNameUse.Unknown:
                        case NativeMethods.SidNameUse.Computer:
                        case NativeMethods.SidNameUse.Label:
                        case NativeMethods.SidNameUse.LogonSession:
                        default:
                            objectType = Label.Base;
                            break;
                    }
                    
                    resolved.Add(new TypedPrincipal(toResolve[i].Value, objectType));
                    try
                    {
                        resolvedNames.Add(new NamedPrincipal(translated.Name.ToString(), toResolve[i].Value));    
                    }catch {}
                    
                }

                _nativeMethods.CallLSAFreeMemory(names);
                _nativeMethods.CallLSAFreeMemory(domains);

                result.Results = resolved.ToArray();
                result.LocalNames = resolvedNames.ToArray();

                yield return result;
            }
        }

        private bool IsMachineAccount(SecurityIdentifier sid)
        {
            var stringSid = sid.Value;
            return IsMachineAccount(stringSid);
        }

        private bool IsMachineAccount(string sid)
        {
            if (sid.StartsWith(_computerDomainSid))
                return false;

            string machineSid;

            if (_lsaServerOpen)
            {
                GetMachineSidLSA(out machineSid);
            }else if (_samServerOpen)
            {
                GetMachineSid(out machineSid);    
            }
            else
            {
                OpenSAMServer();
                GetMachineSid(out machineSid);
            }

            if (machineSid.StartsWith(_computerDomainSid))
                return false;

            return true;
        }

        public IEnumerable<LocalGroupAPIResult> GetGroupsAndMembers()
        {
            //First open the SAM server if it hasn't already been
            if (!_samServerOpen) OpenSAMServer();

            var groupCache = new ConcurrentBag<LocalGroupAPIResult>();

            GetMachineSid(out var machineSid);

            foreach (var domainName in ListDomainsInServer())
                if (OpenDomainHandle(domainName, out var domainHandle))
                    foreach (var group in GetGroupsFromDomain(domainHandle))
                    {
                        _typeCache.TryAdd(group.ObjectID, new CachedLocalItem(group.Name, Label.LocalGroup));
                        var result = GetLocalGroupMembers(domainHandle, group);
                        groupCache.Add(result);
                    }

            _log.LogTrace("Beginning resolution of local types");
            // We've got all our local groups, now we need to resolve unresolved types
            foreach (var group in groupCache)
            {
                if (!group.Collected)
                    continue;

                var names = new List<NamedPrincipal>();
                var resolvedPrincipals = new List<TypedPrincipal>();

                foreach (var result in group.Results)
                {
                    if (result.ObjectType != Label.Base || !result.ObjectIdentifier.StartsWith(machineSid) ||
                        result.ObjectIdentifier.StartsWith(_computerSID.AccountDomainSid.Value))
                    {
                        resolvedPrincipals.Add(result);
                        continue;
                    }

                    var sid = new SecurityIdentifier(result.ObjectIdentifier);
                    _log.LogTrace("Resolving {Sid} in local", sid.Value);
                    if (!ResolveLocalSid(sid, out var name, out var type))
                    {
                        resolvedPrincipals.Add(result);
                        continue;
                    }

                    names.Add(new NamedPrincipal(name, result.ObjectIdentifier));
                    resolvedPrincipals.Add(new TypedPrincipal(result.ObjectIdentifier, type));
                }

                group.Results = resolvedPrincipals.ToArray();
                group.LocalNames = names.ToArray();

                yield return group;
            }
        }

        public bool OpenDomainHandle(string domainName, out IntPtr domainHandle,
            NativeMethods.DomainAccessMask requestedDomainAccess = NativeMethods.DomainAccessMask.Lookup |
                                                                   NativeMethods.DomainAccessMask.ListAccounts)
        {
            if (_domainHandleManager.GetHandleByName(domainName, out domainHandle))
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

            _log.LogTrace("Adding domain to manager: {domain}, {sid}", domainName, sid.ToString());
            _domainHandleManager.AddMappedDomain(sid, domainName, domainHandle);

            return true;
        }

        public bool OpenBuiltInDomain(out IntPtr domainHandle,
            NativeMethods.DomainAccessMask requestedDomainAccess = NativeMethods.DomainAccessMask.Lookup |
                                                                   NativeMethods.DomainAccessMask.ListAccounts)
        {
            if (_domainHandleManager.GetHandleByName("BUILTIN", out domainHandle))
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

            _domainHandleManager.AddMappedDomain("S-1-5-32", "BUILTIN", domainHandle);

            return true;
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
            if (status != NativeMethods.NtStatus.StatusSuccess)
                throw new APIException("SamEnumerateAliasesInDomain", status);

            if (count == 0)
                yield break;

            for (var i = 0; i < count; i++)
            {
                var data = Marshal.PtrToStructure<NativeMethods.SamRidEnumeration>(rids +
                    i * NativeMethods.SamRidEnumeration.SizeOf);
                _log.LogTrace("Got entry {Name} with RID {Rid}", data.Name, data.Rid);
                var group = new LocalGroup
                {
                    Name = data.Name.ToString(),
                    Rid = data.Rid,
                    ObjectID = $"{_computerSID}-{data.Rid}"
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
                    throw new APIException
                    {
                        Status = status.ToString(),
                        APICall = "SamEnumerateDomainsInSamServer"
                    };

                for (var i = 0; i < count; i++)
                {
                    var data = Marshal.PtrToStructure<NativeMethods.SamRidEnumeration>(domains +
                        i * NativeMethods.SamRidEnumeration.SizeOf);
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
        ///     Reads the members in a specified local group from the open domain. The group is referenced by its RID (Relative
        ///     Identifier).
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
                    _log.LogTrace("Resolving {Sid} in domain", sid);
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

        private bool ResolveLocalSid(SecurityIdentifier identifier, out string name, out Label objectType)
        {
            if (_typeCache.TryGetValue(identifier.Value, out var item))
            {
                _log.LogTrace("ResolveLocalSid - Cache hit for {ID}", identifier.Value);
                name = item.Name;
                objectType = item.Type;
                return true;
            }

            var domainSid = identifier.AccountDomainSid.Value;
            var rid = identifier.Rid();

            _log.LogTrace("ResolveLocalSid - Starting resolution for {ID} in domain {Domain} with RID {rid}",
                identifier.Value, domainSid, rid);

            name = null;
            objectType = Label.Base;

            if (!_domainHandleManager.GetHandleBySid(domainSid, out var handle))
            {
                _log.LogTrace("ResolveLocalSid - Failed to get handle for {SID}", domainSid);
                return false;
            }

            var ridArray = new int[1];
            ridArray[0] = rid;
            var status =
                _nativeMethods.CallSamLookupIdsInDomain(handle, ridArray, out var names, out var use);
            try
            {
                if (status != NativeMethods.NtStatus.StatusSuccess)
                {
                    _log.LogTrace("SamLookupIdsInDomain returned {Status} for {Rid} in domain {Domain}", status, rid,
                        domainSid);
                    name = null;
                    objectType = Label.Base;
                    return false;
                }

                var convertedName = Marshal.PtrToStructure<NativeMethods.UNICODE_STRING>(names);
                name = convertedName.ToString();

                var snu = (NativeMethods.SidNameUse) Marshal.ReadInt32(use, 0);

                switch (snu)
                {
                    case NativeMethods.SidNameUse.User:
                        objectType = Label.LocalUser;
                        break;
                    case NativeMethods.SidNameUse.Group:
                        objectType = Label.LocalGroup;
                        break;
                    case NativeMethods.SidNameUse.Alias:
                        objectType = Label.LocalGroup;
                        break;
                    case NativeMethods.SidNameUse.Domain:
                    case NativeMethods.SidNameUse.WellKnownGroup:
                    case NativeMethods.SidNameUse.DeletedAccount:
                    case NativeMethods.SidNameUse.Invalid:
                    case NativeMethods.SidNameUse.Unknown:
                    case NativeMethods.SidNameUse.Computer:
                    case NativeMethods.SidNameUse.Label:
                    case NativeMethods.SidNameUse.LogonSession:
                    default:
                        objectType = Label.Base;
                        break;
                }

                return true;
            }
            finally
            {
                if (names != IntPtr.Zero) _nativeMethods.CallSamFreeMemory(names);

                if (use != IntPtr.Zero) _nativeMethods.CallSamFreeMemory(use);
            }
        }

        public bool GetMachineSidLSA(out string machineSid)
        {
            if (Cache.GetMachineSid(_computerSID.Value, out machineSid))
                return true;

            if (_cachedMachineSid != null)
            {
                machineSid = _cachedMachineSid;
                return true;
            }

            if (!_lsaServerOpen)
            {
                OpenLSAServer();
            }

            var status = _nativeMethods.CallLsaQueryInformationPolicy(_lsaPolicyHandle,
                NativeMethods.LSAPolicyInformation.PolicyAccountDomainInformation, out var buffer);
            if (status != NativeMethods.NtStatus.StatusSuccess)
            {
                machineSid = DummyMachineSid;
                return false;
            }

            var data = Marshal.PtrToStructure<NativeMethods.POLICY_ACCOUNT_DOMAIN_INFO>(buffer);
            _nativeMethods.CallLSAFreeMemory(buffer);

            var sid = new SecurityIdentifier(data.DomainSid);
            machineSid = sid.Value;
            _cachedMachineSid = machineSid;
            Cache.AddMachineSid(_computerSID.Value, machineSid);
            return true;
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

            if (!OpenBuiltInDomain(out var domainHandle)) return false;

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
        public APIException()
        {
        }

        public APIException(string apiCall, NativeMethods.NtStatus status)
        {
            Status = status.ToString();
            APICall = apiCall;
        }

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

    internal class DomainHandleManager
    {
        private readonly NativeMethods _nativeMethods;
        private readonly Dictionary<string, IntPtr> _nameToHandleMap = new();
        private readonly Dictionary<string, string> _sidToDomainMap = new();

        internal DomainHandleManager(NativeMethods nativeMethods = null)
        {
            _nativeMethods = nativeMethods ?? new NativeMethods();
        }

        internal void AddMappedDomain(SecurityIdentifier sid, string name, IntPtr handle)
        {
            if (name.Equals("Builtin", StringComparison.CurrentCultureIgnoreCase))
            {
                _sidToDomainMap.Add(sid.Value.ToUpper(), name.ToUpper());
                _sidToDomainMap.Add(name.ToUpper(), sid.Value.ToUpper());
            }
            else
            {
                _sidToDomainMap.Add(sid.AccountDomainSid.Value.ToUpper(), name.ToUpper());
                _sidToDomainMap.Add(name.ToUpper(), sid.AccountDomainSid.Value.ToUpper());
            }


            _nameToHandleMap.Add(name.ToUpper(), handle);
        }

        internal void AddMappedDomain(string sid, string name, IntPtr handle)
        {
            _sidToDomainMap.Add(sid.ToUpper(), name.ToUpper());
            _sidToDomainMap.Add(name.ToUpper(), sid.ToUpper());
            _nameToHandleMap.Add(name.ToUpper(), handle);
        }

        internal bool GetHandleByName(string name, out IntPtr domainHandle)
        {
            return _nameToHandleMap.TryGetValue(name.ToUpper(), out domainHandle);
        }

        internal bool GetHandleBySid(string sid, out IntPtr domainHandle)
        {
            if (_sidToDomainMap.TryGetValue(sid.ToUpper(), out var domainName))
                return _nameToHandleMap.TryGetValue(domainName, out domainHandle);

            domainHandle = IntPtr.Zero;
            return false;
        }

        internal bool GetHandleBySid(SecurityIdentifier sid, out IntPtr domainHandle)
        {
            var sidString = sid.AccountDomainSid.Value.ToUpper();
            if (_sidToDomainMap.TryGetValue(sidString, out var domainName))
                return _nameToHandleMap.TryGetValue(domainName, out domainHandle);

            domainHandle = IntPtr.Zero;
            return false;
        }

        internal void Dispose()
        {
            foreach (var kv in _nameToHandleMap.ToList())
            {
                if (kv.Value == IntPtr.Zero) continue;
                _nativeMethods.CallSamCloseHandle(kv.Value);
                _nameToHandleMap[kv.Key] = IntPtr.Zero;
            }

            foreach (var kv in _nameToHandleMap)
            {
            }
        }

        ~DomainHandleManager()
        {
            Dispose();
        }
    }

    internal class CachedLocalItem
    {
        public CachedLocalItem(string name, Label type)
        {
            Name = name;
            Type = type;
        }

        public string Name { get; set; }
        public Label Type { get; set; }
    }
}