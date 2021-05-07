using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using CommonLib.Enums;
using CommonLib.Output;
using Domain = System.DirectoryServices.ActiveDirectory.Domain;

namespace CommonLib
{
    public class LDAPUtils
    {
        private readonly ConcurrentDictionary<string, Domain> _domainCache = new();
        private readonly ConcurrentDictionary<string, LdapConnection> _ldapConnections = new();
        private readonly ConcurrentDictionary<string, LdapConnection> _globalCatalogConnections = new();
        private readonly ConcurrentDictionary<string, string> _domainControllerCache = new();
        private readonly ConcurrentDictionary<string, string> _netbiosCache = new();
        private readonly ConcurrentDictionary<string, string> _hostResolutionMap = new();

        private static readonly string[] ResolutionProps = { "distinguishedname", "samaccounttype", "objectsid", "objectguid", "objectclass", "samaccountname", "msds-groupmsamembership" };
        
        // The following byte stream contains the necessary message to request a NetBios name from a machine
        // http://web.archive.org/web/20100409111218/http://msdn.microsoft.com/en-us/library/system.net.sockets.socket.aspx
        private static readonly byte[] NameRequest =
        {
            0x80, 0x94, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
            0x00, 0x01
        };
        
        private const string NULL_CACHE_KEY = "UNIQUENULL";
        private LDAPConfig _ldapConfig;

        private static LDAPUtils _instance = new LDAPUtils();

        public static void UpdateLDAPConfig(LDAPConfig config)
        {
            _instance.SetLDAPConfig(config);
        }

        public static LDAPUtils Instance => _instance;
        
        private LDAPUtils()
        {
            _ldapConfig = new LDAPConfig();
        }

        private void SetLDAPConfig(LDAPConfig config)
        {
            _ldapConfig = config;
        }

        public static TypedPrincipal ResolveSidAndType(string sid, string domain)
        {
            //This is a duplicated SID object which is weird and makes things unhappy. Throw it out
            if (sid.Contains("0ACNF"))
                return new TypedPrincipal
                {
                    ObjectIdentifier = null,
                    ObjectType = Label.Unknown
                };

            if (WellKnownPrincipal.GetWellKnownPrincipal(sid, domain, out var principal))
                return principal;

            var type = LookupSidType(sid, domain);
            return new TypedPrincipal(sid, type);
        }

        public static Label LookupSidType(string sid, string domain)
        {
            if (Cache.GetSidType(sid, out var type))
                return type;
            
            var hex = Helpers.ConvertSidToHexSid(sid);
            if (hex == null)
                return Label.Unknown;

            var rDomain = GetDomainNameFromSid(sid) ?? domain;

            var result = QueryLDAP($"(objectsid={hex})",SearchScope.Subtree, ResolutionProps, rDomain).DefaultIfEmpty(null).FirstOrDefault();

            type = result?.GetLabel() ?? Label.Unknown;
            Cache.AddType(sid, type);
            return type;
        }

        public static string GetDomainNameFromSid(string sid)
        {
            try
            {
                var parsedSid = new SecurityIdentifier(sid);
                var domainSid = parsedSid.AccountDomainSid?.Value.ToUpper();
                if (domainSid == null)
                    return null;

                if (Cache.GetDomainSidMapping(domainSid, out var domain))
                    return domain;

                domain = GetDomainNameFromSidLdap(sid);
                if (domain != null)
                {
                    Cache.AddSidToDomain(sid, domain);
                }

                return domain;
            }
            catch
            {
                return null;
            }
        }
        
        private static string GetDomainNameFromSidLdap(string sid)
        {
            var hexSid = Helpers.ConvertSidToHexSid(sid);

            if (hexSid == null)
                return null;

            //Search using objectsid first
            var result =
                QueryLDAP($"(&(objectclass=domain)(objectsid={hexSid}))", SearchScope.Subtree,
                    new[] {"distinguishedname"}, globalCatalog: true).DefaultIfEmpty(null).FirstOrDefault();

            if (result != null)
            {
                var domainName = Helpers.DistinguishedNameToDomain(result.DistinguishedName);
                return domainName;
            }

            //Try trusteddomain objects with the securityidentifier attribute
            result =
                QueryLDAP($"(&(objectclass=trusteddomain)(securityidentifier={sid}))", SearchScope.Subtree,
                    new[] {"cn"}, globalCatalog: true).DefaultIfEmpty(null).FirstOrDefault();

            if (result != null)
            {
                var domainName = result.GetProperty("cn");
                return domainName;
            }

            //We didn't find anything so just return null
            return null;
        }

        
        /// <summary>
        /// Performs Attribute Ranged Retrieval
        /// https://docs.microsoft.com/en-us/windows/win32/adsi/attribute-range-retrieval
        /// The function self-determines the range and internally handles the maximum step allowed by the server
        /// </summary>
        /// <param name="distinguishedName"></param>
        /// <param name="attributeName"></param>
        /// <returns></returns>
        public static IEnumerable<string> DoRangedRetrieval(string distinguishedName, string attributeName)
        {
            var domainName = Helpers.DistinguishedNameToDomain(distinguishedName);
            var task = Task.Run(() => CreateLDAPConnection(domainName));
            
            LdapConnection conn;

            try
            {
                conn = task.ConfigureAwait(false).GetAwaiter().GetResult();
            }
            catch
            {
                yield break;
            }

            if (conn == null)
                yield break;

            var index = 0;
            var step = 0;
            var baseString = $"{attributeName}";
            //Example search string: member;range=0-1000
            var currentRange = $"{baseString};range={index}-*";
            var complete = false;

            var searchRequest = CreateSearchRequest($"{attributeName}=*", SearchScope.Base, new[] {currentRange},
                distinguishedName);

            if (searchRequest == null)
                yield break;

            while (true)
            {
                SearchResponse response;
            
                response = (SearchResponse) conn.SendRequest(searchRequest);

                //If we ever get more than one response from here, something is horribly wrong
                if (response?.Entries.Count == 0)
                {
                    var entry = response.Entries[0];
                    //Process the attribute we get back to determine a few things
                    foreach (string attr in entry.Attributes.AttributeNames)
                    {
                        //Set our current range to the name of the attribute, which will tell us how far we are in "paging"
                        currentRange = attr;
                        //Check if the string has the * character in it. If it does, we've reached the end of this search 
                        complete = currentRange.IndexOf("*", 0, StringComparison.Ordinal) > 0;
                        //Set our step to the number of attributes that came back.
                        step = entry.Attributes[currentRange].Count;
                    }

                    foreach (string val in entry.Attributes[currentRange].GetValues(typeof(string)))
                    {
                        yield return val;
                        index++;
                    }
                    
                    if (complete) yield break;

                    currentRange = $"{baseString};range={index}-{index + step}";
                    searchRequest.Attributes.Clear();
                    searchRequest.Attributes.Add(currentRange);
                }
                else
                {
                    //Something went wrong here.
                    yield break;
                }
            }

        }

        /// <summary>
        /// Takes a host in most applicable forms from AD and attempts to resolve it into a SID.
        /// </summary>
        /// <param name="hostname"></param>
        /// <param name="domain"></param>
        /// <returns></returns>
        public static async Task<string> ResolveHostToSid(string hostname, string domain)
        {
            var strippedHost = Helpers.StripServicePrincipalName(hostname).ToUpper().TrimEnd('$');

            if (Instance._hostResolutionMap.TryGetValue(strippedHost, out var sid))
            {
                return sid;
            }

            var normalDomain = await NormalizeDomainName(domain);

            string tempName;
            string tempDomain = null;

            //Step 1: Handle non-IP address values
            if (!IPAddress.TryParse(strippedHost, out _))
            {
                // Format: ABC.TESTLAB.LOCAL
                if (strippedHost.Contains("."))
                {
                    var split = strippedHost.Split('.');
                    tempName = split[0];
                    tempDomain = string.Join(".", split.Skip(1).ToArray());
                }
                // Format: WINDOWS
                else
                {
                    tempName = strippedHost;
                    tempDomain = normalDomain;
                }

                // Add $ to the end of the name to match how computers are stored in AD
                tempName = $"{tempName}$".ToUpper();
                var principal = await ResolveAccountName(tempName, tempDomain);
                sid = principal?.ObjectIdentifier;
                if (sid != null)
                {
                    Instance._hostResolutionMap.TryAdd(strippedHost, sid);
                    return sid;
                }
            }
            
            //Step 2: Try NetWkstaGetInfo
            //Next we'll try calling NetWkstaGetInfo in hopes of getting the NETBIOS name directly from the computer
            //We'll use the hostname that we started with instead of the one from our previous step
            var workstationInfo = await CallNetWkstaGetInfo(strippedHost);
            if (workstationInfo.HasValue)
            {
                tempName = workstationInfo.Value.computer_name;
                tempDomain = workstationInfo.Value.lan_group;
                
                if (string.IsNullOrEmpty(tempDomain))
                    tempDomain = normalDomain;
                
                if (!string.IsNullOrEmpty(tempName))
                {
                    //Append the $ to indicate this is a computer
                    tempName = $"{tempName}$".ToUpper();
                    var principal = await ResolveAccountName(tempName, tempDomain);
                    if (principal != null)
                    {
                        Instance._hostResolutionMap.TryAdd(strippedHost, sid);
                        return sid;
                    }
                }
            }
            
            //Step 3: Socket magic
            // Attempt to request the NETBIOS name of the computer directly
            if (RequestNetbiosNameFromComputer(strippedHost, normalDomain, out tempName))
            {
                tempDomain ??= normalDomain;
                tempName = $"{tempName}$".ToUpper();
                
                var principal = await ResolveAccountName(tempName, tempDomain);
                sid = principal?.ObjectIdentifier;
                if (sid != null)
                {
                    Instance._hostResolutionMap.TryAdd(strippedHost, sid);
                    return sid;
                }
            }
            
            //Try DNS resolution next
            string resolvedHostname;
            try
            {
                resolvedHostname = (await Dns.GetHostEntryAsync(strippedHost)).HostName;
            }
            catch
            {
                resolvedHostname = null;
            }

            if (resolvedHostname != null)
            {
                var splitName = resolvedHostname.Split('.');
                tempName = $"{splitName[0]}$".ToUpper();
                tempDomain = string.Join(".", splitName.Skip(1));
                
                var principal = await ResolveAccountName(tempName, tempDomain);
                sid = principal?.ObjectIdentifier;
                if (sid != null)
                {
                    Instance._hostResolutionMap.TryAdd(strippedHost, sid);
                    return sid;
                }
            }

            //If we get here, everything has failed, and life is very sad.
            tempName = strippedHost;
            tempDomain = normalDomain;

            if (tempName.Contains("."))
            {
                Instance._hostResolutionMap.TryAdd(strippedHost, tempName);
                return tempName;
            }
            
            tempName = $"{tempName}.{tempDomain}";
            Instance._hostResolutionMap.TryAdd(strippedHost, tempName);
            return tempName;
        }
        
        /// <summary>
        /// Uses a socket and a set of bytes to request the NETBIOS name from a remote computer
        /// </summary>
        /// <param name="server"></param>
        /// <param name="domain"></param>
        /// <param name="netbios"></param>
        /// <returns></returns>
        private static bool RequestNetbiosNameFromComputer(string server, string domain, out string netbios)
        {
            var receiveBuffer = new byte[1024];
            var requestSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                //Set receive timeout to 1 second
                requestSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, 1000);
                EndPoint remoteEndpoint;

                //We need to create an endpoint to bind too. If its an IP, just use that.
                if (IPAddress.TryParse(server, out var parsedAddress)) remoteEndpoint = new IPEndPoint(parsedAddress, 137);
                else
                {
                    //If its not an IP, we're going to try and resolve it from DNS
                    try
                    {
                        IPAddress address;
                        if (server.Contains("."))
                        {
                            address = Dns
                                .GetHostAddresses(server).First(x => x.AddressFamily == AddressFamily.InterNetwork);
                        }
                        else
                        {
                            address = Dns.GetHostAddresses($"{server}.{domain}")[0];
                        }

                        if (address == null)
                        {
                            netbios = null;
                            return false;
                        }

                        remoteEndpoint = new IPEndPoint(address, 137);
                    }
                    catch
                    {
                        //Failed to resolve an IP, so return null
                        netbios = null;
                        return false;
                    }
                }

                var originEndpoint = new IPEndPoint(IPAddress.Any, 0);
                requestSocket.Bind(originEndpoint);

                try
                {
                    requestSocket.SendTo(NameRequest, remoteEndpoint);
                    var receivedByteCount = requestSocket.ReceiveFrom(receiveBuffer, ref remoteEndpoint);
                    if (receivedByteCount >= 90)
                    {
                        netbios = new ASCIIEncoding().GetString(receiveBuffer, 57, 16).Trim('\0', ' ');
                        return true;
                    }

                    netbios = null;
                    return false;
                }
                catch (SocketException)
                {
                    netbios = null;
                    return false;
                }
            }
            finally
            {
                //Make sure we close the socket if its open
                requestSocket.Close();
            }
        }

        /// <summary>
        /// Calls the NetWkstaGetInfo API on a hostname
        /// </summary>
        /// <param name="hostname"></param>
        /// <returns></returns>
        private static async Task<WorkstationInfo100?> CallNetWkstaGetInfo(string hostname)
        {
            if (!await Helpers.CheckPort(hostname))
                return null;

            var wkstaData = IntPtr.Zero;
            try
            {
                var result = NetWkstaGetInfo(hostname, 100, out wkstaData);
                if (result != 0)
                    return null;

                var wkstaInfo = Marshal.PtrToStructure<WorkstationInfo100>(wkstaData);
                return wkstaInfo;
            }
            finally
            {
                if (wkstaData != IntPtr.Zero)
                    NetApiBufferFree(wkstaData);
            }
        }
        
        /// <summary>
        /// Attempts to convert a bare account name (usually from session enumeration) to its corresponding ID and object type
        /// </summary>
        /// <param name="name"></param>
        /// <param name="domain"></param>
        /// <returns></returns>
        public static async Task<TypedPrincipal> ResolveAccountName(string name, string domain)
        {
            if (Cache.GetPrefixedValue(name, domain, out var id) && Cache.GetSidType(id, out var type))
            {
                return new TypedPrincipal
                {
                    ObjectIdentifier = id,
                    ObjectType = type
                };
            }

            var d = await NormalizeDomainName(domain);
            var result = QueryLDAP($"(samaccountname={name})", SearchScope.Subtree, ResolutionProps,
                d).DefaultIfEmpty(null).FirstOrDefault();

            if (result == null)
                return null;
            
            type = result.GetLabel();
            id = result.GetObjectIdentifier();

            if (id == null)
            {
                Logging.Debug($"No resolved ID for {name}");
                return null;
            }
            Cache.AddPrefixedValue(name, domain, id);
            Cache.AddType(id, type);

            id = WellKnownPrincipal.TryConvert(id, domain);
            
            return new TypedPrincipal
            {
                ObjectIdentifier = id,
                ObjectType = type
            };
        }

        /// <summary>
        /// Attempts to convert a distinguishedname to its corresponding ID and object type.
        /// </summary>
        /// <param name="dn">DistinguishedName</param>
        /// <returns>A <c>TypedPrincipal</c> object with the SID and Label</returns>
        public static async Task<TypedPrincipal> ResolveDistinguishedName(string dn)
        {
            if (Cache.GetConvertedValue(dn, out var id) && Cache.GetSidType(id, out var type))
            {
                return new TypedPrincipal
                {
                    ObjectIdentifier = id,
                    ObjectType = type
                };
            }

            var domain = Helpers.DistinguishedNameToDomain(dn);
            var result = QueryLDAP("(objectclass=*)", SearchScope.Base, ResolutionProps, domainName: domain, adsPath: dn)
                    .DefaultIfEmpty(null).FirstOrDefault();

            if (result == null)
            {
                Logging.Debug($"No result found for {dn}");
                return null;
            }

            type = result.GetLabel();
            id = result.GetObjectIdentifier();

            if (id == null)
            {
                Logging.Debug($"No resolved ID for {dn}");
                return null;
            }
            Cache.AddConvertedValue(dn, id);
            Cache.AddType(id, type);

            id = WellKnownPrincipal.TryConvert(id, domain);
            
            return new TypedPrincipal
            {
                ObjectIdentifier = id,
                ObjectType = type
            };
        }

        /// <summary>
        /// Performs an LDAP query using the parameters specified by the user.
        /// </summary>
        /// <param name="ldapFilter">LDAP filter</param>
        /// <param name="scope">SearchScope to query</param>
        /// <param name="props">LDAP properties to fetch for each object</param>
        /// <param name="includeAcl">Include the DACL and Owner values in the NTSecurityDescriptor</param>
        /// <param name="showDeleted">Include deleted objects</param>
        /// <param name="domainName">Domain to query</param>
        /// <param name="adsPath">ADS path to limit the query too</param>
        /// <param name="globalCatalog">Use the global catalog instead of the regular LDAP server</param>
        /// <param name="skipCache">Skip the connection cache and force a new connection. You must dispose of this connection yourself.</param>
        /// <returns>All LDAP search results matching the specified parameters</returns>
        public static IEnumerable<SearchResultEntry> QueryLDAP(string ldapFilter, SearchScope scope,
            string[] props, string domainName = null, bool includeAcl = false, bool showDeleted = false, string adsPath = null, bool globalCatalog = false, bool skipCache = false)
        {
            Logging.Debug("Creating ldap connection");
            var task = globalCatalog
                ? Task.Run(() => CreateGlobalCatalogConnection(domainName))
                : Task.Run(() => CreateLDAPConnection(domainName, skipCache));

            LdapConnection conn;
            try
            {
                conn = task.ConfigureAwait(false).GetAwaiter().GetResult();
            }
            catch
            {
                yield break;
            }
            
            if (conn == null)
            {
                Logging.Debug("LDAP connection is null");
                yield break;
            }

            var request = CreateSearchRequest(ldapFilter, scope, props, domainName, adsPath, showDeleted);

            if (request == null)
            {
                Logging.Debug("Search request is null");
                yield break;
            }

            var pageControl = new PageResultRequestControl(500);
            request.Controls.Add(pageControl);

            if (includeAcl)
                request.Controls.Add(new SecurityDescriptorFlagControl
                {
                    SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner
                });

            PageResultResponseControl pageResponse = null;
            while (true)
            {
                SearchResponse response;
                try
                {
                    Logging.Debug("Sending LDAP request");
                    response = (SearchResponse) conn.SendRequest(request);
                    if (response != null)
                        pageResponse = (PageResultResponseControl) response.Controls
                            .Where(x => x is PageResultRequestControl).DefaultIfEmpty(null).FirstOrDefault();
                }
                catch (Exception e)
                {
                    Logging.Debug($"Exception in LDAP loop: {e}");
                    yield break;
                }

                if (response == null || pageResponse == null)
                {
                    continue;
                }

                foreach (SearchResultEntry entry in response.Entries)
                    yield return entry;

                if (pageResponse.Cookie.Length == 0 || response.Entries.Count == 0)
                    yield break;

                pageControl.Cookie = pageResponse.Cookie;
            }
        }

        /// <summary>
        /// Creates a SearchRequest object for use in querying LDAP.
        /// </summary>
        /// <param name="filter">LDAP filter</param>
        /// <param name="scope">SearchScope to query</param>
        /// <param name="attributes">LDAP properties to fetch for each object</param>
        /// <param name="domainName">Domain to query</param>
        /// <param name="adsPath">ADS path to limit the query too</param>
        /// <param name="showDeleted">Include deleted objects in results</param>
        /// <returns>A built SearchRequest</returns>
        private static SearchRequest CreateSearchRequest(string filter, SearchScope scope, string[] attributes,
            string domainName = null, string adsPath = null, bool showDeleted = false)
        {
            var domain = GetDomain(domainName);
            if (domain == null)
                return null;

            var dName = domain.Name;
            var adPath = adsPath?.Replace("LDAP://", "") ?? $"DC={domainName.Replace(".", ",DC=")}";

            var request = new SearchRequest(adPath, filter, scope, attributes);
            request.Controls.Add(new SearchOptionsControl(SearchOption.DomainScope));
            if (showDeleted)
                request.Controls.Add(new ShowDeletedControl());

            return request;
        }

        /// <summary>
        /// Creates a LDAP connection to a global catalog server
        /// </summary>
        /// <param name="domainName">Domain to connect too</param>
        /// <returns>A connected LdapConnection or null</returns>
        private static async Task<LdapConnection> CreateGlobalCatalogConnection(string domainName = null)
        {
            var domain = GetDomain(domainName);
            if (domain == null)
            {
                Logging.Debug($"Unable to contact domain {domainName}");
                return null;
            }
            
            string targetServer;
            if (Instance._ldapConfig.Server != null) targetServer = Instance._ldapConfig.Server;
            else
            {
                if (!Instance._domainControllerCache.TryGetValue(domain.Name, out targetServer))
                    targetServer = await GetUsableDomainController(domain);
            }
            
            if (targetServer == null)
                return null;

            if (Instance._globalCatalogConnections.TryGetValue(targetServer, out var connection))
                return connection;

            connection = new LdapConnection(new LdapDirectoryIdentifier(targetServer, 3268));
            
            connection.SessionOptions.ProtocolVersion = 3;

            if (Instance._ldapConfig.DisableSigning)
            {
                connection.SessionOptions.Sealing = false;
                connection.SessionOptions.Signing = false;
            }
            
            //Force kerberos auth
            connection.AuthType = AuthType.Kerberos;

            Instance._globalCatalogConnections.TryAdd(targetServer, connection);
            return connection;
        }

        /// <summary>
        /// Creates an LDAP connection with appropriate options based off the ldap configuration. Caches connections
        /// </summary>
        /// <param name="domainName">The domain to connect too</param>
        /// <param name="skipCache">Skip the connection cache</param>
        /// <returns>A connected LDAP connection or null</returns>
        private static async Task<LdapConnection> CreateLDAPConnection(string domainName = null, bool skipCache = false)
        {
            var domain = GetDomain(domainName);
            if (domain == null)
            {
                Logging.Debug($"Unable to contact domain {domainName}");
                return null;
            }

            string targetServer;
            if (Instance._ldapConfig.Server != null) targetServer = Instance._ldapConfig.Server;
            else
            {
                if (!Instance._domainControllerCache.TryGetValue(domain.Name, out targetServer))
                    targetServer = await GetUsableDomainController(domain);
            }
            
            if (targetServer == null)
                return null;
            
            if (!skipCache)
                if (Instance._ldapConnections.TryGetValue(targetServer, out var conn))
                    return conn;

            var port = Instance._ldapConfig.GetPort();
            var ident = new LdapDirectoryIdentifier(targetServer, port, false, false);
            var connection = new LdapConnection(ident) {Timeout = new TimeSpan(0, 0, 5, 0)};
            if (Instance._ldapConfig.Username != null)
            {
                var cred = new NetworkCredential(Instance._ldapConfig.Username, Instance._ldapConfig.Password, domain.Name);
                connection.Credential = cred;
            }

            //These options are important!
            connection.SessionOptions.ProtocolVersion = 3;
            connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;

            if (Instance._ldapConfig.DisableSigning)
            {
                connection.SessionOptions.Sealing = false;
                connection.SessionOptions.Signing = false;
            }

            if (Instance._ldapConfig.SSL)
                connection.SessionOptions.SecureSocketLayer = true;

            //Force kerberos auth
            connection.AuthType = AuthType.Kerberos;

            if (!skipCache)
                Instance._ldapConnections.TryAdd(targetServer, connection);

            return connection;
        }

        internal static Forest GetForest(string domainName = null)
        {
            try
            {
                if (domainName == null && Instance._ldapConfig.Username == null)
                    return Forest.GetCurrentForest();

                var domain = GetDomain(domainName);
                return domain?.Forest;
            }
            catch
            {
                return null;
            }
            
        }

        internal static Domain GetDomain(string domainName = null)
        {
            var cacheKey = domainName ?? NULL_CACHE_KEY;
            if (Instance._domainCache.TryGetValue(cacheKey, out var domain))
            {
                return domain;
            }

            try
            {
                DirectoryContext context;
                if (Instance._ldapConfig.Username != null)
                {
                    context = domainName != null
                        ? new DirectoryContext(DirectoryContextType.Domain, domainName, Instance._ldapConfig.Username,
                            Instance._ldapConfig.Password)
                        : new DirectoryContext(DirectoryContextType.Domain, Instance._ldapConfig.Username,
                            Instance._ldapConfig.Password);
                }
                else
                {
                    context = domainName != null
                        ? new DirectoryContext(DirectoryContextType.Domain, domainName)
                        : new DirectoryContext(DirectoryContextType.Domain);
                }

                domain = Domain.GetDomain(context);
            }
            catch
            {
                domain = null;
            }

            Instance._domainCache.TryAdd(cacheKey, domain);
            return domain;
        }
        
        private static async Task<string> GetUsableDomainController(Domain domain, bool gc = false)
        {
            var port = gc ? 3268 : Instance._ldapConfig.GetPort();
            var pdc = domain.PdcRoleOwner.Name;
            if (await Helpers.CheckPort(pdc, port))
            {
                Instance._domainControllerCache.TryAdd(domain.Name, pdc);
                Logging.Debug($"Found usable Domain Controller for {domain.Name} : {pdc}");
                return pdc;
            }

            //If the PDC isn't reachable loop through the rest
            foreach (DomainController domainController in domain.DomainControllers)
            {
                var name = domainController.Name;
                if (!await Helpers.CheckPort(name, port)) continue;
                Logging.Debug($"Found usable Domain Controller for {domain.Name} : {name}");
                Instance._domainControllerCache.TryAdd(domain.Name, name);
                return name;
            }

            //If we get here, somehow we didn't get any usable DCs. Save it off as null
            Instance._domainControllerCache.TryAdd(domain.Name, null);
            Logging.Debug($"Unable to find usable domain controller for {domain.Name}");
            return null;
        }
        
        /// <summary>
        /// Normalizes a domain name to its full DNS name
        /// </summary>
        /// <param name="domain"></param>
        /// <returns></returns>
        internal static async Task<string> NormalizeDomainName(string domain)
        {
            var resolved = domain;

            if (resolved.Contains("."))
                return domain.ToUpper();

            resolved = await ResolveDomainNetbiosToDns(domain) ?? domain;

            return resolved.ToUpper();
        }
        
        /// <summary>
        /// Turns a domain Netbios name into its FQDN using the DsGetDcName function (TESTLAB -> TESTLAB.LOCAL)
        /// </summary>
        /// <param name="domainName"></param>
        /// <returns></returns>
        internal static async Task<string> ResolveDomainNetbiosToDns(string domainName)
        {
            var key = domainName.ToUpper();
            if (Instance._netbiosCache.TryGetValue(key, out var flatName))
                return flatName;

            var domain = GetDomain(domainName);
            if (domain == null)
                return domainName.ToUpper();
            
            var computerName = Instance._ldapConfig.Server ?? await GetUsableDomainController(domain);

            var result = DsGetDcName(computerName, domainName, null, null,
                (uint)(DSGETDCNAME_FLAGS.DS_IS_FLAT_NAME | DSGETDCNAME_FLAGS.DS_RETURN_DNS_NAME),
                out var pDomainControllerInfo);

            try
            {
                if (result == 0)
                {
                    var info = Marshal.PtrToStructure<DOMAIN_CONTROLLER_INFO>(pDomainControllerInfo);
                    flatName = info.DomainName;
                }
            }
            finally
            {
                if (pDomainControllerInfo != IntPtr.Zero)
                    NetApiBufferFree(pDomainControllerInfo);
            }

            Instance._netbiosCache.TryAdd(key, flatName);
            return flatName;
        }
        
        
        #region NetAPI PInvoke Calls
        [DllImport("netapi32.dll", SetLastError = true)]
        private static extern int NetWkstaGetInfo(
            [MarshalAs(UnmanagedType.LPWStr)] string serverName,
            uint level,
            out IntPtr bufPtr);

        private struct WorkstationInfo100
        {

            public int platform_id;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string computer_name;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string lan_group;
            public int ver_major;
            public int ver_minor;
        }

        [DllImport("Netapi32.dll", SetLastError = true)]
        private static extern int NetApiBufferFree(IntPtr Buffer);
        #endregion
        
        #region DSGetDcName Imports
        [DllImport("Netapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern int DsGetDcName
        (
            [MarshalAs(UnmanagedType.LPTStr)]
            string ComputerName,
            [MarshalAs(UnmanagedType.LPTStr)]
            string DomainName,
            [In] GuidClass DomainGuid,
            [MarshalAs(UnmanagedType.LPTStr)]
            string SiteName,
            uint Flags,
            out IntPtr pDOMAIN_CONTROLLER_INFO
        );

        [StructLayout(LayoutKind.Sequential)]
        public class GuidClass
        {
            public Guid TheGuid;
        }

        [Flags]
        public enum DSGETDCNAME_FLAGS : uint
        {
            DS_FORCE_REDISCOVERY = 0x00000001,
            DS_DIRECTORY_SERVICE_REQUIRED = 0x00000010,
            DS_DIRECTORY_SERVICE_PREFERRED = 0x00000020,
            DS_GC_SERVER_REQUIRED = 0x00000040,
            DS_PDC_REQUIRED = 0x00000080,
            DS_BACKGROUND_ONLY = 0x00000100,
            DS_IP_REQUIRED = 0x00000200,
            DS_KDC_REQUIRED = 0x00000400,
            DS_TIMESERV_REQUIRED = 0x00000800,
            DS_WRITABLE_REQUIRED = 0x00001000,
            DS_GOOD_TIMESERV_PREFERRED = 0x00002000,
            DS_AVOID_SELF = 0x00004000,
            DS_ONLY_LDAP_NEEDED = 0x00008000,
            DS_IS_FLAT_NAME = 0x00010000,
            DS_IS_DNS_NAME = 0x00020000,
            DS_RETURN_DNS_NAME = 0x40000000,
            DS_RETURN_FLAT_NAME = 0x80000000
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct DOMAIN_CONTROLLER_INFO
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

        #endregion
    }
}