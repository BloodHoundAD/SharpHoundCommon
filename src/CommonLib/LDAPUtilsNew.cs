using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.Exceptions;
using SharpHoundCommonLib.LDAPQueries;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.Processors;
using Domain = System.DirectoryServices.ActiveDirectory.Domain;

namespace SharpHoundCommonLib
{
    public class LDAPUtilsNew : ILDAPUtils
    {
        private readonly ILogger _log;
        private readonly NativeMethods _nativeMethods;
        private readonly PortScanner _portScanner;
        
        //Ldap Retry Vars
        private static readonly TimeSpan MinBackoffDelay = TimeSpan.FromSeconds(2);
        private static readonly TimeSpan MaxBackoffDelay = TimeSpan.FromSeconds(20);
        private const int BackoffDelayMultiplier = 2;
        private const int MaxRetries = 3;
        
        private LDAPConfig _ldapConfig = new();
        private readonly ConcurrentDictionary<LDAPConnectionCacheKey, LdapConnectionWrapper> _ldapConnections = new();
        private static readonly ConcurrentBag<string> UnresolvableGcHits = new();
        private static readonly ConcurrentDictionary<string, DomainInfo> CachedDomainInfo = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, string> NETBIOSCache = new();
        private static readonly ConcurrentDictionary<string, ResolvedWellKnownPrincipal> SeenWellKnownPrincipals = new();
        private static readonly ConcurrentDictionary<string, byte> DomainControllers = new();
        
        private class ResolvedWellKnownPrincipal
        {
            public string DomainName { get; set; }
            public string WkpId { get; set; }
        }
        
        /// <summary>
        ///     Creates a new instance of LDAP Utils with defaults
        /// </summary>
        public LDAPUtilsNew()
        {
            _nativeMethods = new NativeMethods();
            _portScanner = new PortScanner();
            _log = Logging.LogProvider.CreateLogger("LDAPUtils");
        }
        
        /// <summary>
        ///     Creates a new instance of LDAP utils and allows overriding implementations
        /// </summary>
        /// <param name="nativeMethods"></param>
        /// <param name="scanner"></param>
        /// <param name="log"></param>
        public LDAPUtilsNew(NativeMethods nativeMethods = null, PortScanner scanner = null, ILogger log = null)
        {
            _nativeMethods = nativeMethods ?? new NativeMethods();
            _portScanner = scanner ?? new PortScanner();
            _log = log ?? Logging.LogProvider.CreateLogger("LDAPUtils");
        }
        
        public void SetLDAPConfig(LDAPConfig config)
        {
            _ldapConfig = config ?? throw new ArgumentNullException(nameof(config));
            _log.LogTrace("Setting new LDAP config and clearing existing LDAP connections from cache");
            //Close out any existing LDAP connections to request a new incoming config
            foreach (var kv in _ldapConnections)
            {
                kv.Value.Connection.Dispose();
            }
            _ldapConnections.Clear();
        }

        public bool TestLDAPConfig(string domain)
        {
            try
            {
                var result = QueryLDAP(new LDAPFilter().AddDomains().GetFilter(), SearchScope.Subtree,
                    CommonProperties.ObjectID, domain, throwException: true).DefaultIfEmpty(null).FirstOrDefault();
                var distinguishedName = result?.DistinguishedName;
                if (distinguishedName == null)
                {
                    _log.LogWarning("Connection test to domain {Domain} failed: unable to enumerate a domain object", domain);
                    return false;
                }
                _log.LogTrace("Result object from LDAP connection test to domain {Domain} has distinguishedname: {dn}", domain, distinguishedName);
                _log.LogInformation("Connection test to domain {Domain} successful", domain);
                return true;
            }
            catch (LDAPQueryException e)
            {
                _log.LogError(e, "LDAP Connection Test to domain {Domain} failed", domain);
                return false;
            }
        }

        public string[] GetUserGlobalCatalogMatches(string name, string domain)
        {
            var tempName = name.ToUpper();
            if (UnresolvableGcHits.Contains(tempName))
            {
                return Array.Empty<string>();
            }
            if (Cache.GetGlobalCatalogMatches(tempName, out var potentialSids))
            {
                return potentialSids;
            }

            //Ask for all users with the same samaccountname
            var query = new LDAPFilter().AddUsers($"samaccountname={tempName}").GetFilter();
            //Using the global catalog allows us to get all potential matches across domains
            var results = QueryLDAP(query, SearchScope.Subtree, CommonProperties.ObjectSID, domain,
                globalCatalog: true).Select(x => x.GetSid()).Where(x => x != null).ToArray();

            if (results.Length == 0)
            {
                UnresolvableGcHits.Add(tempName);
            }
            else
            {
                Cache.AddGlobalCatalogMatches(tempName, results);
            }

            return results;
        }

        public bool ResolveIDAndType(string id, string domain, out TypedPrincipal resolvedPrincipal)
        {
            if (id == null)
            {
                throw new ArgumentNullException(nameof(id));
            }

            if (domain == null)
            {
                throw new ArgumentNullException(nameof(domain));
            }
            
            //Any id with 0ACNF is a duplicated object which are really hard to resolve. Hopefully this will solve itself on replication, but we cant do anything about it here
            if (id.Contains("0ACNF"))
            {
                _log.LogWarning("Attempted to resolve sid with duplicate sentinel: {Sid}", id);
                resolvedPrincipal = null;
                return false;
            }

            if (GetWellKnownPrincipal(id, domain, out resolvedPrincipal))
                return true;

            var success = LookupObjectType(id, domain, out var type);
            if (!success) return false;
            resolvedPrincipal = new TypedPrincipal
            {
                ObjectIdentifier = id,
                ObjectType = type
            };
            return true;
        }
        
        /// <summary>
        /// Attempt to look up the object type for a SID
        /// </summary>
        /// <param name="sid"></param>
        /// <param name="domain"></param>
        /// <param name="type"></param>
        /// <returns>true if the sid was resolved to a type successfully, otherwise false</returns>
        private bool LookupSidType(string sid, string domain, out Label type)
        {
            if (Cache.GetIDType(sid, out type))
                return true;

            if (!GetDomainNameFromSid(sid, out var resolvedDomain))
            {
                resolvedDomain = domain;
            }

            var result =
                QueryLDAP(CommonFilters.SpecificSID(sid), SearchScope.Subtree, CommonProperties.TypeResolutionProps,
                        resolvedDomain)
                    .DefaultIfEmpty(null).FirstOrDefault();

            if (result == null)
            {
                type = Label.Base;
                return false;
            }

            type = result.GetLabel();
            Cache.AddType(sid, type);
            return true;
        }

        /// <summary>
        /// Attempt to look up the object type for a GUID
        /// </summary>
        /// <param name="guid"></param>
        /// <param name="domain"></param>
        /// <param name="type"></param>
        /// <returns>true if the GUID was resolved to a type successfully, otherwise false</returns>
        private bool LookupGuidType(string guid, string domain, out Label type)
        {
            if (Cache.GetIDType(guid, out type))
                return true;

            var hex = Helpers.ConvertGuidToHexGuid(guid);
            if (hex == null)
                return false;

            var result =
                QueryLDAP($"(objectguid={hex})", SearchScope.Subtree, CommonProperties.TypeResolutionProps, domain)
                    .DefaultIfEmpty(null).FirstOrDefault();

            if (result == null)
            {
                return false;
            }
            type = result.GetLabel();
            Cache.AddType(guid, type);
            return true;
        }

        public TypedPrincipal ResolveCertTemplateByProperty(string propValue, string propName, string containerDN, string domainName)
        {
            throw new System.NotImplementedException();
        }

        public bool LookupObjectType(string id, string domain, out Label objectType)
        {
            if (Cache.GetIDType(id, out objectType))
            {
                return true;
            }

            return id.StartsWith("S-1-5") ? LookupSidType(id, domain, out objectType) : LookupGuidType(id, domain, out objectType);
        }

        public bool GetDomainNameFromSid(string sid, out string domainName)
        {
            string domainSid;
            try
            {
                var parsedSid = new SecurityIdentifier(sid);
                domainSid = parsedSid.AccountDomainSid?.Value.ToUpper();
            }
            catch
            {
                domainName = default;
                return false;
            }

            if (domainSid == null)
            {
                domainName = default;
                return false;
            }

            if (Cache.GetDomainSidMapping(domainSid, out domainName))
            {
                return true;
            }
            
            if (CachedDomainInfo.TryGetValue(domainSid, out var info))
            {
                Cache.AddDomainSidMapping(domainSid, info.DomainFQDN);
                Cache.AddDomainSidMapping(info.DomainFQDN, domainSid);
                domainName = info.DomainFQDN;
                return true;
            }
            
            _log.LogDebug("Attempting to resolve sid {sid} to domain name", domainSid);
            try
            {
                domainName = GetDomainNameFromSidLdap(domainSid, domainName);
                if (domainName != null)
                {
                    _log.LogDebug("Resolved {DomainSid} to {DomainName}", domainSid, domainName);
                    Cache.AddDomainSidMapping(domainSid, domainName);
                    Cache.AddDomainSidMapping(domainName, domainSid);
                    return true;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }
        
        private string GetDomainNameFromSidLdap(string sid, string domain)
        {
            //Search using objectsid first
            var filter = new LDAPFilter().AddDomains().AddFilter(CommonFilters.SpecificSID(sid), true);
            var result =
                QueryLDAP(filter.GetFilter(), SearchScope.Subtree,
                    new[] { LDAPProperties.DistinguishedName }, domain, globalCatalog: true).DefaultIfEmpty(null).FirstOrDefault();

            if (result != null)
            {
                var domainName = Helpers.DistinguishedNameToDomain(result.DistinguishedName);
                return domainName;
            }
            
            filter = new LDAPFilter().AddTrustedDomains().AddFilter($"(securityidentifier={sid})", true);

            //Try trusteddomain objects with the securityidentifier attribute
            result =
                QueryLDAP(filter.GetFilter(), SearchScope.Subtree,
                    new[] { LDAPProperties.CanonicalName }, domain, globalCatalog: true).DefaultIfEmpty(null).FirstOrDefault();

            if (result != null)
            {
                var domainName = result.GetProperty(LDAPProperties.CanonicalName);
                return domainName;
            }

            //We didn't find anything so just return null
            return null;
        }

        public async Task<(bool, string)> GetSidFromDomainName(string domainName)
        {
            if (domainName == null)
            {
                return (false, "");
            }
            if (Cache.GetDomainSidMapping(domainName.ToUpper(), out var domainSid))
            {
                return (true, domainSid);
            }

            if (CachedDomainInfo.TryGetValue(domainName.ToUpper(), out var info) && !string.IsNullOrEmpty(info.DomainSID))
            {
                return (true, info.DomainSID);
            }

            //If our ldap config doesn't have a server set, we can try and resolve this using an ldap connection with the RootDSE info
            if (_ldapConfig.Server == null)
            {
                try
                {
                    var connection = await CreateLDAPConnectionWrapper(domainName);
                    if (!string.IsNullOrEmpty(connection.DomainInfo?.DomainSID))
                    {
                        return (true, connection.DomainInfo.DomainSID);
                    }
                }
                catch
                {
                    //pass
                }
            }

            var domainObject = GetDomain(domainName);
            var sid = domainObject?.GetDirectoryEntry().GetSid();
            if (sid != null)
            {
                Cache.AddDomainSidMapping(sid, domainName);
                Cache.AddDomainSidMapping(domainName, sid);
                Cache.AddDomainSidMapping(domainObject.Name, sid);
                Cache.AddDomainSidMapping(sid, domainObject.Name);
                return (true, sid);
            }

            return (false, "");
        }

        public string ConvertWellKnownPrincipal(string sid, string domain)
        {
            if (!WellKnownPrincipal.GetWellKnownPrincipal(sid, out _)) return sid;
            
            //S-1-5-9 is enterprise domain controllers, which lives in the forest root
            if (sid != "S-1-5-9") return $"{domain}-{sid}".ToUpper();
            
            var forest = GetForest(domain)?.Name;
            if (forest == null) _log.LogWarning("Error getting forest for domain {Domain}, enterprise dc sid is likely incorrect", domain);
            return $"{forest ?? "UNKNOWN"}-{sid}".ToUpper();
        }

        public bool GetWellKnownPrincipal(string sid, string domain, out TypedPrincipal commonPrincipal)
        {
            if (!WellKnownPrincipal.GetWellKnownPrincipal(sid, out commonPrincipal)) return false;
            var tempDomain = domain ?? GetDomain()?.Name ?? "UNKNOWN";
            commonPrincipal.ObjectIdentifier = ConvertWellKnownPrincipal(sid, tempDomain);
            SeenWellKnownPrincipals.TryAdd(commonPrincipal.ObjectIdentifier, new ResolvedWellKnownPrincipal
            {
                DomainName = domain,
                WkpId = sid
            });
            return true;
        }

        public bool ConvertLocalWellKnownPrincipal(SecurityIdentifier sid, string computerDomainSid, string computerDomain,
            out TypedPrincipal principal)
        {
            if (WellKnownPrincipal.GetWellKnownPrincipal(sid.Value, out var common))
            {
                //The everyone and auth users principals are special and will be converted to the domain equivalent
                if (sid.Value is "S-1-1-0" or "S-1-5-11")
                {
                    GetWellKnownPrincipal(sid.Value, computerDomain, out principal);
                    return true;
                }

                //Use the computer object id + the RID of the sid we looked up to create our new principal
                principal = new TypedPrincipal
                {
                    ObjectIdentifier = $"{computerDomainSid}-{sid.Rid()}",
                    ObjectType = common.ObjectType switch
                    {
                        Label.User => Label.LocalUser,
                        Label.Group => Label.LocalGroup,
                        _ => common.ObjectType
                    }
                };

                return true;
            }

            principal = null;
            return false;
        }

        public Domain GetDomain(string domainName = null)
        {
            throw new System.NotImplementedException();
        }

        public void AddDomainController(string domainControllerSID)
        {
            DomainControllers.TryAdd(domainControllerSID, new byte());
        }

        public IEnumerable<OutputBase> GetWellKnownPrincipalOutput(string domain)
        {
            foreach (var wkp in SeenWellKnownPrincipals)
            {
                WellKnownPrincipal.GetWellKnownPrincipal(wkp.Value.WkpId, out var principal);
                OutputBase output = principal.ObjectType switch
                {
                    Label.User => new User(),
                    Label.Computer => new Computer(),
                    Label.Group => new Group(),
                    Label.GPO => new GPO(),
                    Label.Domain => new OutputTypes.Domain(),
                    Label.OU => new OU(),
                    Label.Container => new Container(),
                    Label.Configuration => new Container(),
                    _ => throw new ArgumentOutOfRangeException()
                };

                output.Properties.Add("name", $"{principal.ObjectIdentifier}@{wkp.Value.DomainName}".ToUpper());
                var domainSid = GetSidFromDomainName(wkp.Value.DomainName);
                output.Properties.Add("domainsid", domainSid);
                output.Properties.Add("domain", wkp.Value.DomainName.ToUpper());
                output.ObjectIdentifier = wkp.Key;
                yield return output;
            }

            var entdc = GetBaseEnterpriseDC(domain);
            entdc.Members = DomainControllers.Select(x => new TypedPrincipal(x.Key, Label.Computer)).ToArray();
            yield return entdc;
        }

        public IEnumerable<string> DoRangedRetrieval(string distinguishedName, string attributeName)
        {
            throw new System.NotImplementedException();
        }

        public Task<string> ResolveHostToSid(string hostname, string domain)
        {
            throw new System.NotImplementedException();
        }

        public bool ResolveAccountName(string name, string domain, out TypedPrincipal resolvedAccount)
        {
            throw new System.NotImplementedException();
        }

        public bool ResolveDistinguishedName(string dn, out TypedPrincipal resolvedPrincipal)
        {
            throw new System.NotImplementedException();
        }

        public IEnumerable<ISearchResultEntry> QueryLDAP(LDAPQueryOptions options)
        {
            throw new System.NotImplementedException();
        }

        public IEnumerable<ISearchResultEntry> QueryLDAP(string ldapFilter, SearchScope scope, string[] props, CancellationToken cancellationToken,
            string domainName, bool includeAcl = false, bool showDeleted = false, string adsPath = null,
            bool globalCatalog = false, bool skipCache = false, bool throwException = false)
        {
            throw new System.NotImplementedException();
        }

        public IEnumerable<ISearchResultEntry> QueryLDAP(string ldapFilter, SearchScope scope, string[] props, string domainName, bool includeAcl = false,
            bool showDeleted = false, string adsPath = null, bool globalCatalog = false, bool skipCache = false,
            bool throwException = false)
        {
            throw new System.NotImplementedException();
        }

        public Forest GetForest(string domainName = null)
        {
            throw new System.NotImplementedException();
        }

        public ActiveDirectorySecurityDescriptor MakeSecurityDescriptor()
        {
            throw new System.NotImplementedException();
        }

        public string BuildLdapPath(string dnPath, string domain)
        {
            throw new System.NotImplementedException();
        }

        public bool IsDomainController(string computerObjectId, string domainName)
        {
            throw new System.NotImplementedException();
        }
        /// <summary>
        ///     Creates an LDAP connection with appropriate options based off the ldap configuration. Caches connections
        /// </summary>
        /// <param name="domainName">The domain to connect too</param>
        /// <param name="skipCache">Skip the connection cache</param>
        /// <param name="authType">Auth type to use. Defaults to Kerberos. Use Negotiate for netonly/cross trust(forest) scenarios</param>
        /// <param name="globalCatalog">Use global catalog or not</param>
        /// <exception cref="NoLdapDataException">A connection was established but no data was returned</exception>
        /// <exception cref="LdapAuthenticationException">The authentication method was not supported by the server</exception>
        /// <exception cref="LdapConnectionException">A LdapException occurred with an unhandled error code. The inner exception contains the original LDAP exception</exception>
        /// <returns>A connected LDAP connection or null</returns>

        private async Task<LdapConnectionWrapper> CreateLDAPConnectionWrapper(string domainName, bool skipCache = false,
            AuthType authType = AuthType.Kerberos, bool globalCatalog = false)
        {
            // Step 1: If domain passed in is non-null, skip this step
            // - Call GetDomain with a null domain to get the user's current domain
            // Step 2: Take domain passed in to the function or resolved from step 1
            // - Try an ldap connection on SSL
            // - If ServerUnavailable - Try an ldap connection on non-SSL
            //     Step 3: Pass the domain to GetDomain to resolve to a better name (potentially)
            //     - If we get a better name, repeat step 2 with the new name
            //     Step 4:
            // - Use GetDomain to get a domain object along with a list of domain controllers
            // - Try the primary domain controller on both ssl/non-ssl
            // - Loop over domain controllers and try each on ssl/non-ssl
            
            //If a server has been manually specified, we should never get past this block for opsec reasons
            if (_ldapConfig.Server != null)
            {
                if (!skipCache)
                {
                    if (GetCachedConnection(_ldapConfig.Server, globalCatalog, out var conn))
                    {
                        return conn;
                    }
                }
                
                var singleServerConn = CreateLDAPConnection(_ldapConfig.Server, authType, globalCatalog);
                if (singleServerConn == null) return new LdapConnectionWrapper
                {
                    Connection = null,
                    DomainInfo = null
                };
                var cacheKey = new LDAPConnectionCacheKey(_ldapConfig.Server, globalCatalog);
                _ldapConnections.AddOrUpdate(cacheKey, singleServerConn, (_, ldapConnection) =>
                {
                    ldapConnection.Connection.Dispose();
                    return singleServerConn;
                });
                return singleServerConn;
            }
            
            //Take the incoming domain name and Upper/Trim it. If the name is null, we'll have to use GetDomain to figure out the user's domain context
            var domain = domainName?.ToUpper().Trim() ?? ResolveDomainToFullName(null);

            //If our domain is STILL null, we're not going to get anything reliable, so exit out
            if (domain == null)
            {
                return new LdapConnectionWrapper
                {
                    Connection = null,
                    DomainInfo = null
                };
            }
            
            if (!skipCache)
            {
                if (GetCachedConnection(domain, globalCatalog, out var conn))
                {
                    return conn;
                }
            }

            var connectionWrapper = CreateLDAPConnection(domain, authType, globalCatalog);
            //If our connection isn't null, it means we have a good connection
            if (connectionWrapper != null)
            {
                if (domainName != null)
                {
                    CachedDomainInfo.TryAdd(domainName, connectionWrapper.DomainInfo);    
                }
                var cacheKey = new LDAPConnectionCacheKey(domain, globalCatalog);
                _ldapConnections.AddOrUpdate(cacheKey, connectionWrapper, (_, ldapConnection) =>
                {
                    ldapConnection.Connection.Dispose();
                    return connectionWrapper;
                });
                return connectionWrapper;
            }

            //If our incoming domain name wasn't null, try to re-resolve the name for a better potential match and then retry
            if (domainName != null)
            {
                var newDomain = ResolveDomainToFullName(domainName);
                if (!string.IsNullOrEmpty(newDomain) && !newDomain.Equals(domain, StringComparison.OrdinalIgnoreCase))
                {
                    //Set our domain name to the newly resolved value for future steps
                    domain = newDomain;
                    if (!skipCache)
                    {
                        //Check our cache again, maybe the new name works
                        if (GetCachedConnection(domain, globalCatalog, out var conn))
                        {
                            return conn;
                        }
                    }

                    connectionWrapper = CreateLDAPConnection(domain, authType, globalCatalog);
                    //If our connection isn't null, it means we have a good connection
                    if (connectionWrapper != null)
                    {
                        CachedDomainInfo.TryAdd(domainName, connectionWrapper.DomainInfo);    
                        var cacheKey = new LDAPConnectionCacheKey(domain, globalCatalog);
                        _ldapConnections.AddOrUpdate(cacheKey, connectionWrapper, (_, ldapConnection) =>
                        {
                            ldapConnection.Connection.Dispose();
                            return connectionWrapper;
                        });
                        return connectionWrapper;
                    }
                }
            }
            
            //Next step, look for domain controllers
            var domainObj = GetDomain(domain);
            if (domainObj?.Name == null)
            {
                return null;
            }

            //Start with the PDC of the domain and see if we can connect
            var pdc = domainObj.PdcRoleOwner.Name;
            connectionWrapper = await CreateLDAPConnectionWithPortCheck(pdc, authType, globalCatalog);
            if (connectionWrapper != null)
            {
                var cacheKey = new LDAPConnectionCacheKey(domain, globalCatalog);
                _ldapConnections.AddOrUpdate(cacheKey, connectionWrapper, (_, ldapConnection) =>
                {
                    ldapConnection.Connection.Dispose();
                    return connectionWrapper;
                });
                return connectionWrapper;
            }

            //Loop over all other domain controllers and see if we can make a good connection to any
            foreach (DomainController dc in domainObj.DomainControllers)
            {
                connectionWrapper = await CreateLDAPConnectionWithPortCheck(dc.Name, authType, globalCatalog);
                if (connectionWrapper != null)
                {
                    var cacheKey = new LDAPConnectionCacheKey(domain, globalCatalog);
                    _ldapConnections.AddOrUpdate(cacheKey, connectionWrapper, (_, ldapConnection) =>
                    {
                        ldapConnection.Connection.Dispose();
                        return connectionWrapper;
                    });
                    return connectionWrapper;
                }
            }

            return new LdapConnectionWrapper()
            {
                Connection = null,
                DomainInfo = null
            };
        }

        private bool GetCachedConnection(string domain, bool globalCatalog, out LdapConnectionWrapper connectionWrapper)
        {
            var domainName = domain;
            if (CachedDomainInfo.TryGetValue(domain.ToUpper(), out var resolved))
            {
                domainName = resolved.DomainFQDN;
            }
            var key = new LDAPConnectionCacheKey(domainName, globalCatalog);
            return _ldapConnections.TryGetValue(key, out connectionWrapper); 
        }

        private async Task<LdapConnectionWrapper> CreateLDAPConnectionWithPortCheck(string target, AuthType authType, bool globalCatalog)
        {
            if (globalCatalog)
            {
                if (await _portScanner.CheckPort(target, _ldapConfig.GetGCPort(true)) || (!_ldapConfig.ForceSSL &&
                        await _portScanner.CheckPort(target, _ldapConfig.GetGCPort(false))))
                {
                    return CreateLDAPConnection(target, authType, true);
                }
            }
            else
            {
                if (await _portScanner.CheckPort(target, _ldapConfig.GetPort(true)) || (!_ldapConfig.ForceSSL && await _portScanner.CheckPort(target, _ldapConfig.GetPort(false))))
                {
                    return CreateLDAPConnection(target, authType, false);
                }
            }
            
            return null;
        }

        
        private LdapConnectionWrapper CreateLDAPConnection(string target, AuthType authType, bool globalCatalog)
        {
            //Lets build a new connection
            //Always try SSL first
            var connection = CreateConnectionHelper(target, true, authType, globalCatalog);
            var connectionResult = TestConnection(connection);
            DomainInfo info;

            if (connectionResult.Success)
            {
                var domain = connectionResult.DomainInfo.DomainFQDN;
                if (!CachedDomainInfo.ContainsKey(domain))
                {
                    var baseDomainInfo = connectionResult.DomainInfo;
                    baseDomainInfo.DomainSID =  GetDomainSid(connection, baseDomainInfo);
                    baseDomainInfo.DomainNetbiosName = GetDomainNetbiosName(connection, baseDomainInfo);
                    _log.LogInformation("Got info for domain: {info}", baseDomainInfo);
                    CachedDomainInfo.TryAdd(baseDomainInfo.DomainFQDN, baseDomainInfo);
                    CachedDomainInfo.TryAdd(baseDomainInfo.DomainNetbiosName, baseDomainInfo);
                    CachedDomainInfo.TryAdd(baseDomainInfo.DomainSID, baseDomainInfo);
                    if (!string.IsNullOrEmpty(baseDomainInfo.DomainSID))
                    {
                        Cache.AddDomainSidMapping(baseDomainInfo.DomainFQDN, baseDomainInfo.DomainSID);
                        if (!string.IsNullOrEmpty(baseDomainInfo.DomainNetbiosName))
                        {
                            Cache.AddDomainSidMapping(baseDomainInfo.DomainNetbiosName, baseDomainInfo.DomainSID);    
                        }
                    }

                    if (!string.IsNullOrEmpty(baseDomainInfo.DomainNetbiosName))
                    {
                        NETBIOSCache.TryAdd(baseDomainInfo.DomainFQDN, baseDomainInfo.DomainNetbiosName);
                    }

                    info = baseDomainInfo;
                }
                else
                {
                    CachedDomainInfo.TryGetValue(domain, out info);
                }
                return new LdapConnectionWrapper
                {
                    Connection = connection,
                    DomainInfo = info
                };
            }

            CheckAndThrowException(connectionResult.Exception);

            //If we're not allowing fallbacks to LDAP from LDAPS, just return here
            if (_ldapConfig.ForceSSL)
            {
                return null;
            }
            //If we get to this point, it means we have an unsuccessful connection, but our error code doesn't indicate an outright failure
            //Try a new connection without SSL
            connection = CreateConnectionHelper(target, false, authType, globalCatalog);

            connectionResult = TestConnection(connection);
                
            if (connectionResult.Success)
            {
                var domain = connectionResult.DomainInfo.DomainFQDN;
                if (!CachedDomainInfo.ContainsKey(domain.ToUpper()))
                {
                    var baseDomainInfo = connectionResult.DomainInfo;
                    baseDomainInfo.DomainSID =  GetDomainSid(connection, baseDomainInfo);
                    baseDomainInfo.DomainNetbiosName = GetDomainNetbiosName(connection, baseDomainInfo);
                    CachedDomainInfo.TryAdd(baseDomainInfo.DomainFQDN, baseDomainInfo);
                    CachedDomainInfo.TryAdd(baseDomainInfo.DomainNetbiosName, baseDomainInfo);
                    CachedDomainInfo.TryAdd(baseDomainInfo.DomainSID, baseDomainInfo);
                    
                    if (!string.IsNullOrEmpty(baseDomainInfo.DomainSID))
                    {
                        Cache.AddDomainSidMapping(baseDomainInfo.DomainFQDN, baseDomainInfo.DomainSID);
                    }

                    if (!string.IsNullOrEmpty(baseDomainInfo.DomainNetbiosName))
                    {
                        Cache.AddDomainSidMapping(baseDomainInfo.DomainNetbiosName, baseDomainInfo.DomainSID);
                    }

                    info = baseDomainInfo;
                }else
                {
                    CachedDomainInfo.TryGetValue(domain, out info);
                }
                return new LdapConnectionWrapper
                {
                    Connection = connection,
                    DomainInfo = info
                };
            }
            
            CheckAndThrowException(connectionResult.Exception);
            return null;
        }
        
        
        private LdapConnection CreateConnectionHelper(string directoryIdentifier, bool ssl, AuthType authType, bool globalCatalog)
        {
            var port = globalCatalog ? _ldapConfig.GetGCPort(ssl) : _ldapConfig.GetPort(ssl);
            var identifier = new LdapDirectoryIdentifier(directoryIdentifier, port, false, false);
            var connection = new LdapConnection(identifier) { Timeout = new TimeSpan(0, 0, 5, 0) };
            SetupLdapConnection(connection, true, authType);
            return connection;
        }
        
        private void SetupLdapConnection(LdapConnection connection, bool ssl, AuthType authType)
        {
            //These options are important!
            connection.SessionOptions.ProtocolVersion = 3;
            //Referral chasing does not work with paged searches 
            connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
            if (ssl)
            {
                connection.SessionOptions.SecureSocketLayer = true;    
            }
            
            if (_ldapConfig.DisableSigning)
            {
                connection.SessionOptions.Sealing = false;
                connection.SessionOptions.Signing = false;
            }
            
            if (_ldapConfig.DisableCertVerification)
                connection.SessionOptions.VerifyServerCertificate = (_, _) => true;
            
            if (_ldapConfig.Username != null)
            {
                var cred = new NetworkCredential(_ldapConfig.Username, _ldapConfig.Password);
                connection.Credential = cred;
            }
            
            connection.AuthType = authType;
        }
        
        private string GetDomainNetbiosName(LdapConnection connection, DomainInfo info)
        {
            try
            {
                var searchRequest = new SearchRequest($"CN=Partitions,{info.DomainConfigurationPath}",
                    "(&(nETBIOSName=*)(dnsRoot=*))",
                    SearchScope.Subtree, new[] { LDAPProperties.NetbiosName, LDAPProperties.DnsRoot });

                var response = (SearchResponse)connection.SendRequest(searchRequest);
                if (response == null || response.Entries.Count == 0)
                {
                    return "";
                }

                foreach (SearchResultEntry entry in response.Entries)
                {
                    var root = entry.GetProperty(LDAPProperties.DnsRoot);
                    var netbios = entry.GetProperty(LDAPProperties.NetbiosName);
                    _log.LogInformation(root);
                    _log.LogInformation(netbios);

                    if (root.ToUpper().Equals(info.DomainFQDN))
                    {
                        return netbios.ToUpper();
                    }
                }

                return "";
            }
            catch (LdapException e)
            {
                _log.LogWarning("Failed grabbing netbios name from ldap for {domain}: {e}", info.DomainFQDN, e);
                return "";
            }
        }

        private string GetDomainSid(LdapConnection connection, DomainInfo info)
        {
            try
            {
                //This ldap filter searches for domain controllers
                //Searches for any accounts with a UAC value inclusive of 8192 bitwise
                //8192 is the flag for SERVER_TRUST_ACCOUNT, which is set only on Domain Controllers
                var searchRequest = new SearchRequest(info.DomainSearchBase,
                    "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
                    SearchScope.Subtree, new[] { "objectsid"});

                var response = (SearchResponse)connection.SendRequest(searchRequest);
                if (response == null || response.Entries.Count == 0)
                {
                    return "";
                }

                var entry = response.Entries[0];
                var sid = entry.GetSid();
                return sid.Substring(0, sid.LastIndexOf('-')).ToUpper();
            }
            catch (LdapException)
            {
                _log.LogWarning("Failed grabbing domainsid from ldap for {domain}", info.DomainFQDN);
                return "";
            }
        }
        
        private static void CheckAndThrowException(LdapException ldapException)
        {
            //A null error code with success false indicates that we successfully created a connection but got no data back, this is generally because our AuthType isn't compatible.
            //AuthType Kerberos will only work across trusts in very specific scenarios. Alternatively, we don't have read rights.
            //Throw this exception for clients to handle
            if (ldapException.ErrorCode is (int)LdapErrorCodes.KerberosAuthType or (int)ResultCode.InsufficientAccessRights)
            {
                throw new NoLdapDataException(ldapException.ErrorCode);
            }

            //We shouldn't ever hit this in theory, but we'll error out if its the case
            if (ldapException.ErrorCode is (int)ResultCode.InappropriateAuthentication)
            {
                throw new LdapAuthenticationException(ldapException);
            }

            //Any other error we dont have specific ways to handle
            if (ldapException.ErrorCode != (int)ResultCode.Unavailable && ldapException.ErrorCode != (int)ResultCode.Busy)
            {
                throw new LdapConnectionException(ldapException);
            }
        }

        private static LdapConnectionTestResult TestConnection(LdapConnection connection)
        {
            try
            {
                //Attempt an initial bind. If this fails, likely auth is invalid, or its not a valid target
                connection.Bind();
            }
            catch (LdapException e)
            {
                connection.Dispose();
                return new LdapConnectionTestResult(false, e, null, null);
            }

            try
            {
                //Do an initial search request to get the rootDSE
                //This ldap filter is equivalent to (objectclass=*)
                var searchRequest = new SearchRequest("", new LDAPFilter().AddAllObjects().GetFilter(),
                    SearchScope.Base, null);
                searchRequest.Controls.Add(new SearchOptionsControl(SearchOption.DomainScope));

                var response = (SearchResponse)connection.SendRequest(searchRequest);
                if (response?.Entries == null)
                {
                    connection.Dispose();
                    return new LdapConnectionTestResult(false, null, null, null);
                }

                if (response.Entries.Count == 0)
                {
                    connection.Dispose();
                    return new LdapConnectionTestResult(false, new LdapException((int)LdapErrorCodes.KerberosAuthType), null, null);
                }

                var entry = response.Entries[0];
                var baseDN = entry.GetProperty(LDAPProperties.RootDomainNamingContext).ToUpper().Trim();
                var configurationDN = entry.GetProperty(LDAPProperties.ConfigurationNamingContext).ToUpper().Trim();
                var schemaDN = entry.GetProperty(LDAPProperties.SchemaNamingContext).ToUpper().Trim();
                var domainname = Helpers.DistinguishedNameToDomain(baseDN).ToUpper().Trim();
                var servername = entry.GetProperty(LDAPProperties.ServerName);
                var compName = servername.Substring(0, servername.IndexOf(',')).Substring(3).Trim();
                var fullServerName = $"{compName}.{domainname}".ToUpper().Trim();

                return new LdapConnectionTestResult(true, null, new DomainInfo
                {
                    DomainConfigurationPath = configurationDN,
                    DomainSearchBase = baseDN,
                    DomainFQDN = domainname,
                    SchemaPath = schemaDN
                }, fullServerName);
            }
            catch (LdapException e)
            {
                try
                {
                    connection.Dispose();
                }
                catch
                {
                    //pass
                }
                return new LdapConnectionTestResult(false, e, null, null);
            }
        }
            
        public class LdapConnectionTestResult
        {
            public bool Success { get; set; }
            public LdapException Exception { get; set; }
            public DomainInfo DomainInfo { get; set; }
            public string ServerName { get; set; }

            public LdapConnectionTestResult(bool success, LdapException e, DomainInfo info, string server)
            {
                Success = success;
                Exception = e;
                DomainInfo = info;
                ServerName = server;
            }
        }
        
        private string ResolveDomainToFullName(string domain)
        {
            if (string.IsNullOrEmpty(domain))
            {
                return GetDomain()?.Name.ToUpper().Trim();
            }
            
            if (CachedDomainInfo.TryGetValue(domain.ToUpper(), out var info))
            {
                return info.DomainFQDN;
            }

            return GetDomain(domain)?.Name.ToUpper().Trim();
        }
    }
}