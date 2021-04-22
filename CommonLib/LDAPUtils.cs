using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Net;
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
        
        private readonly string[] ResolutionProps = { "distinguishedname", "samaccounttype", "objectsid", "objectguid", "objectclass", "samaccountname", "msds-groupmsamembership" };
        
        private const string NULL_CACHE_KEY = "UNIQUENULL";
        private readonly LDAPConfig _ldapConfig;

        private static LDAPUtils _instance;

        public static void CreateInstance(LDAPConfig config)
        {
            _instance = new LDAPUtils(config);
        }

        public static LDAPUtils Instance => _instance;

        private LDAPUtils(LDAPConfig config)
        {
            _ldapConfig = config;
        }

        /// <summary>
        /// Converts a distinguishedname to its corresponding SID and object type.
        /// </summary>
        /// <param name="dn">DistinguishedName</param>
        /// <returns>A <c>TypedPrincipal</c> object with the SID and Label</returns>
        public async Task<TypedPrincipal> ResolveDistinguishedName(string dn)
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
            var result =
                await QueryLDAP("(objectclass=*)", SearchScope.Base, ResolutionProps, domainName: domain, adsPath: dn)
                    .DefaultIfEmpty(null).FirstOrDefaultAsync();

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
            Cache.AddType(dn, type);

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
        public async IAsyncEnumerable<SearchResultEntry> QueryLDAP(string ldapFilter, SearchScope scope,
            string[] props, bool includeAcl = false, bool showDeleted = false, string domainName = null, string adsPath = null, bool globalCatalog = false, bool skipCache = false)
        {
            Logging.Debug("Creating ldap connection");
            var conn = globalCatalog
                ? await CreateGlobalCatalogConnection(domainName)
                : await CreateLDAPConnection(domainName, skipCache);

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
        private SearchRequest CreateSearchRequest(string filter, SearchScope scope, string[] attributes,
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
        private async Task<LdapConnection> CreateGlobalCatalogConnection(string domainName = null)
        {
            var domain = GetDomain(domainName);
            if (domain == null)
            {
                Logging.Debug($"Unable to contact domain {domainName}");
                return null;
            }
            
            string targetServer;
            if (_ldapConfig.Server != null) targetServer = _ldapConfig.Server;
            else
            {
                if (!_domainControllerCache.TryGetValue(domain.Name, out targetServer))
                    targetServer = await GetUsableDomainController(domain);
            }
            
            if (targetServer == null)
                return null;

            if (_globalCatalogConnections.TryGetValue(targetServer, out var connection))
                return connection;

            connection = new LdapConnection(new LdapDirectoryIdentifier(targetServer, 3268));
            
            connection.SessionOptions.ProtocolVersion = 3;

            if (_ldapConfig.DisableSigning)
            {
                connection.SessionOptions.Sealing = false;
                connection.SessionOptions.Signing = false;
            }
            
            //Force kerberos auth
            connection.AuthType = AuthType.Kerberos;

            _globalCatalogConnections.TryAdd(targetServer, connection);
            return connection;
        }

        /// <summary>
        /// Creates an LDAP connection with appropriate options based off the ldap configuration. Caches connections
        /// </summary>
        /// <param name="domainName">The domain to connect too</param>
        /// <param name="skipCache">Skip the connection cache</param>
        /// <returns>A connected LDAP connection or null</returns>
        private async Task<LdapConnection> CreateLDAPConnection(string domainName = null, bool skipCache = false)
        {
            var domain = GetDomain(domainName);
            if (domain == null)
            {
                Logging.Debug($"Unable to contact domain {domainName}");
                return null;
            }

            string targetServer;
            if (_ldapConfig.Server != null) targetServer = _ldapConfig.Server;
            else
            {
                if (!_domainControllerCache.TryGetValue(domain.Name, out targetServer))
                    targetServer = await GetUsableDomainController(domain);
            }
            
            if (targetServer == null)
                return null;
            
            if (!skipCache)
                if (_ldapConnections.TryGetValue(targetServer, out var conn))
                    return conn;

            var port = _ldapConfig.GetPort();
            var ident = new LdapDirectoryIdentifier(targetServer, port, false, false);
            var connection = new LdapConnection(ident) {Timeout = new TimeSpan(0, 0, 5, 0)};
            if (_ldapConfig.Username != null)
            {
                var cred = new NetworkCredential(_ldapConfig.Username, _ldapConfig.Password, domain.Name);
                connection.Credential = cred;
            }

            //These options are important!
            connection.SessionOptions.ProtocolVersion = 3;
            connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;

            if (_ldapConfig.DisableSigning)
            {
                connection.SessionOptions.Sealing = false;
                connection.SessionOptions.Signing = false;
            }

            if (_ldapConfig.SSL)
                connection.SessionOptions.SecureSocketLayer = true;

            //Force kerberos auth
            connection.AuthType = AuthType.Kerberos;

            if (!skipCache)
                _ldapConnections.TryAdd(targetServer, connection);

            return connection;
        }

        internal Forest GetForest(string domainName = null)
        {
            try
            {
                if (domainName == null && _ldapConfig.Username == null)
                    return Forest.GetCurrentForest();

                var domain = GetDomain(domainName);
                return domain?.Forest;
            }
            catch
            {
                return null;
            }
            
        }

        internal Domain GetDomain(string domainName = null)
        {
            var cacheKey = domainName ?? NULL_CACHE_KEY;
            if (_domainCache.TryGetValue(cacheKey, out var domain))
            {
                return domain;
            }

            try
            {
                DirectoryContext context;
                if (_ldapConfig.Username != null)
                {
                    context = domainName != null
                        ? new DirectoryContext(DirectoryContextType.Domain, domainName, _ldapConfig.Username,
                            _ldapConfig.Password)
                        : new DirectoryContext(DirectoryContextType.Domain, _ldapConfig.Username,
                            _ldapConfig.Password);
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

            _domainCache.TryAdd(cacheKey, domain);
            return domain;
        }
        
        private async Task<string> GetUsableDomainController(Domain domain, bool gc = false)
        {
            var port = gc ? 3268 : _ldapConfig.GetPort();
            var pdc = domain.PdcRoleOwner.Name;
            if (await Helpers.CheckPort(pdc, port))
            {
                _domainControllerCache.TryAdd(domain.Name, pdc);
                Logging.Debug($"Found usable Domain Controller for {domain.Name} : {pdc}");
                return pdc;
            }

            //If the PDC isn't reachable loop through the rest
            foreach (DomainController domainController in domain.DomainControllers)
            {
                var name = domainController.Name;
                if (!await Helpers.CheckPort(name, port)) continue;
                Logging.Debug($"Found usable Domain Controller for {domain.Name} : {name}");
                _domainControllerCache.TryAdd(domain.Name, name);
                return name;
            }

            //If we get here, somehow we didn't get any usable DCs. Save it off as null
            _domainControllerCache.TryAdd(domain.Name, null);
            Logging.Debug($"Unable to find usable domain controller for {domain.Name}");
            return null;
        }
    }
}