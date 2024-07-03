using System;
using System.Collections.Concurrent;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.Exceptions;
using SharpHoundCommonLib.LDAPQueries;
using SharpHoundCommonLib.Processors;
using SharpHoundRPC.NetAPINative;

namespace SharpHoundCommonLib {
    public class LdapConnectionPool : IDisposable{
        private readonly ConcurrentBag<LdapConnectionWrapper> _connections;
        private readonly ConcurrentBag<LdapConnectionWrapper> _globalCatalogConnection;
        private readonly SemaphoreSlim _semaphore;
        private readonly string _identifier;
        private readonly string _poolIdentifier;
        private readonly LDAPConfig _ldapConfig;
        private readonly ILogger _log;
        private readonly PortScanner _portScanner;
        private readonly NativeMethods _nativeMethods;

        public LdapConnectionPool(string identifier, string poolIdentifier, LDAPConfig config, int maxConnections = 10, PortScanner scanner = null, NativeMethods nativeMethods = null, ILogger log = null) {
            _connections = new ConcurrentBag<LdapConnectionWrapper>();
            _globalCatalogConnection = new ConcurrentBag<LdapConnectionWrapper>();
            _semaphore = new SemaphoreSlim(maxConnections, maxConnections);
            _identifier = identifier;
            _poolIdentifier = poolIdentifier;
            _ldapConfig = config;
            _log = log ?? Logging.LogProvider.CreateLogger("LdapConnectionPool");
            _portScanner = scanner ?? new PortScanner();
            _nativeMethods = nativeMethods ?? new NativeMethods();
        }

        public async Task<(bool Success, LdapConnectionWrapper ConnectionWrapper, string Message)> GetConnectionAsync() {
            await _semaphore.WaitAsync();
            if (!_connections.TryTake(out var connectionWrapper)) {
                var (success, connection, message) = await CreateNewConnection();
                if (!success) {
                    //If we didn't get a connection, immediately release the semaphore so we don't have hanging ones
                    _semaphore.Release();
                    return (false, null, message);
                }
            
                connectionWrapper = connection;
            }

            return (true, connectionWrapper, null);
        }

        public async Task<(bool Success, LdapConnectionWrapper connectionWrapper, string Message)>
            GetConnectionForSpecificServerAsync(string server, bool globalCatalog) {
            await _semaphore.WaitAsync();

            var result= CreateNewConnectionForServer(server, globalCatalog);
            if (!result.Success) {
                //If we didn't get a connection, immediately release the semaphore so we don't have hanging ones
                _semaphore.Release();
            }

            return result;
        }

        public async Task<(bool Success, LdapConnectionWrapper ConnectionWrapper, string Message)> GetGlobalCatalogConnectionAsync() {
            await _semaphore.WaitAsync();
            if (!_globalCatalogConnection.TryTake(out var connectionWrapper)) {
                var (success, connection, message) = await CreateNewConnection(true);
                if (!success) {
                    //If we didn't get a connection, immediately release the semaphore so we don't have hanging ones
                    _semaphore.Release();
                    return (false, null, message);
                }

                connectionWrapper = connection;
            }

            return (true, connectionWrapper, null);
        }

        public void ReleaseConnection(LdapConnectionWrapper connectionWrapper, bool connectionFaulted = false) {
            _semaphore.Release();
            if (!connectionFaulted) {
                if (connectionWrapper.GlobalCatalog) {
                    _globalCatalogConnection.Add(connectionWrapper);
                }
                else {
                    _connections.Add(connectionWrapper);    
                }
            }
            else {
                connectionWrapper.Connection.Dispose();
            }
        }
    
        public void Dispose() {
            while (_connections.TryTake(out var wrapper)) {
                wrapper.Connection.Dispose();
            }
        }

        private async Task<(bool Success, LdapConnectionWrapper Connection, string Message)> CreateNewConnection(bool globalCatalog = false) {
            if (!string.IsNullOrWhiteSpace(_ldapConfig.Server)) {
                return CreateNewConnectionForServer(_ldapConfig.Server, globalCatalog);
            }

            if (CreateLdapConnection(_identifier.ToUpper().Trim(), globalCatalog, out var connectionWrapper)) {
                _log.LogDebug("Successfully created ldap connection for domain: {Domain} using strategy 1. SSL: {SSl}", _identifier, connectionWrapper.Connection.SessionOptions.SecureSocketLayer);
                return (true, connectionWrapper, "");
            }
        
            string tempDomainName;
        
            var dsGetDcNameResult = _nativeMethods.CallDsGetDcName(null, _identifier,
                (uint)(NetAPIEnums.DSGETDCNAME_FLAGS.DS_FORCE_REDISCOVERY |
                       NetAPIEnums.DSGETDCNAME_FLAGS.DS_RETURN_DNS_NAME |
                       NetAPIEnums.DSGETDCNAME_FLAGS.DS_DIRECTORY_SERVICE_REQUIRED));
            if (dsGetDcNameResult.IsSuccess) {
                tempDomainName = dsGetDcNameResult.Value.DomainName;

                if (!tempDomainName.Equals(_identifier, StringComparison.OrdinalIgnoreCase) &&
                    CreateLdapConnection(tempDomainName, globalCatalog, out connectionWrapper)) {
                    _log.LogDebug(
                        "Successfully created ldap connection for domain: {Domain} using strategy 2 with name {NewName}",
                        _identifier, tempDomainName);
                    return (true, connectionWrapper, "");
                }
            
                var server = dsGetDcNameResult.Value.DomainControllerName.TrimStart('\\');

                var result =
                    await CreateLDAPConnectionWithPortCheck(server, globalCatalog);
                if (result.success) {
                    _log.LogDebug(
                        "Successfully created ldap connection for domain: {Domain} using strategy 3 to server {Server}",
                        _identifier, server);
                    return (true, result.connection, "");
                }
            }
        
            if (!LdapUtils.GetDomain(_identifier, _ldapConfig, out var domainObject) || domainObject.Name == null) {
                //If we don't get a result here, we effectively have no other ways to resolve this domain, so we'll just have to exit out
                _log.LogDebug(
                    "Could not get domain object from GetDomain, unable to create ldap connection for domain {Domain}",
                    _identifier);
                return (false, null, "Unable to get domain object for further strategies");
            }
            tempDomainName = domainObject.Name.ToUpper().Trim();
        
            if (!tempDomainName.Equals(_identifier, StringComparison.OrdinalIgnoreCase) &&
                CreateLdapConnection(tempDomainName, globalCatalog, out connectionWrapper)) {
                _log.LogDebug(
                    "Successfully created ldap connection for domain: {Domain} using strategy 4 with name {NewName}",
                    _identifier, tempDomainName);
                return (true, connectionWrapper, "");
            }
        
            var primaryDomainController = domainObject.PdcRoleOwner.Name;
            var portConnectionResult =
                await CreateLDAPConnectionWithPortCheck(primaryDomainController, globalCatalog);
            if (portConnectionResult.success) {
                _log.LogDebug(
                    "Successfully created ldap connection for domain: {Domain} using strategy 5 with to pdc {Server}",
                    _identifier, primaryDomainController);
                return (true, connectionWrapper, "");
            }
        
            foreach (DomainController dc in domainObject.DomainControllers) {
                portConnectionResult =
                    await CreateLDAPConnectionWithPortCheck(dc.Name, globalCatalog);
                if (portConnectionResult.success) {
                    _log.LogDebug(
                        "Successfully created ldap connection for domain: {Domain} using strategy 6 with to pdc {Server}",
                        _identifier, primaryDomainController);
                    return (true, connectionWrapper, "");
                }
            }

            return (false, null, "All attempted connections failed");
        }
    
        private (bool Success, LdapConnectionWrapper Connection, string Message ) CreateNewConnectionForServer(string identifier, bool globalCatalog = false) {
            if (CreateLdapConnection(identifier, globalCatalog, out var serverConnection)) {
                return (true, serverConnection, "");
            }

            return (false, null, $"Failed to create ldap connection for {identifier}");
        }
    
        private bool CreateLdapConnection(string target, bool globalCatalog,
            out LdapConnectionWrapper connection) {
            var baseConnection = CreateBaseConnection(target, true, globalCatalog);
            if (TestLdapConnection(baseConnection, out var result)) {
                connection = new LdapConnectionWrapper(baseConnection, result.SearchResultEntry, globalCatalog, _poolIdentifier);
                return true;
            }

            try {
                baseConnection.Dispose();
            }
            catch {
                //this is just in case
            }

            if (_ldapConfig.ForceSSL) {
                connection = null;
                return false;
            }

            baseConnection = CreateBaseConnection(target, false, globalCatalog);
            if (TestLdapConnection(baseConnection, out result)) {
                connection = new LdapConnectionWrapper(baseConnection, result.SearchResultEntry, globalCatalog, _poolIdentifier);
                return true;
            }

            try {
                baseConnection.Dispose();
            }
            catch {
                //this is just in case
            }

            connection = null;
            return false;
        }
    
        private LdapConnection CreateBaseConnection(string directoryIdentifier, bool ssl,
            bool globalCatalog) {
            _log.LogDebug("Creating connection for identifier {Identifier}", directoryIdentifier);
            var port = globalCatalog ? _ldapConfig.GetGCPort(ssl) : _ldapConfig.GetPort(ssl);
            var identifier = new LdapDirectoryIdentifier(directoryIdentifier, port, false, false);
            var connection = new LdapConnection(identifier) { Timeout = new TimeSpan(0, 0, 5, 0) };
            
            //These options are important!
            connection.SessionOptions.ProtocolVersion = 3;
            //Referral chasing does not work with paged searches 
            connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
            if (ssl) connection.SessionOptions.SecureSocketLayer = true;
            
            if (_ldapConfig.DisableSigning || ssl) {
                connection.SessionOptions.Signing = false;
                connection.SessionOptions.Sealing = false;
            }
            else {
                connection.SessionOptions.Signing = true;
                connection.SessionOptions.Sealing = true;
            }
            
            if (_ldapConfig.DisableCertVerification)
                connection.SessionOptions.VerifyServerCertificate = (_, _) => true;

            if (_ldapConfig.Username != null) {
                var cred = new NetworkCredential(_ldapConfig.Username, _ldapConfig.Password);
                connection.Credential = cred;
            }

            connection.AuthType = _ldapConfig.AuthType;

            return connection;
        }

        /// <summary>
        ///     Tests whether an LDAP connection is working
        /// </summary>
        /// <param name="connection">The ldap connection object to test</param>
        /// <param name="testResult">The results fo the connection test</param>
        /// <returns>True if connection was successful, false otherwise</returns>
        /// <exception cref="LdapAuthenticationException">Something is wrong with the supplied credentials</exception>
        /// <exception cref="NoLdapDataException">
        ///     A connection "succeeded" but no data was returned. This can be related to
        ///     kerberos auth across trusts or just simply lack of permissions
        /// </exception>
        private bool TestLdapConnection(LdapConnection connection, out LdapConnectionTestResult testResult) {
            testResult = new LdapConnectionTestResult();
            try {
                //Attempt an initial bind. If this fails, likely auth is invalid, or its not a valid target
                connection.Bind();
            }
            catch (LdapException e) {
                //TODO: Maybe look at this and find a better way?
                if (e.ErrorCode is (int)LdapErrorCodes.InvalidCredentials or (int)ResultCode.InappropriateAuthentication) {
                    connection.Dispose();
                    throw new LdapAuthenticationException(e);
                }

                testResult.Message = e.Message;
                testResult.ErrorCode = e.ErrorCode;
                return false;
            }
            catch (Exception e) {
                testResult.Message = e.Message;
                return false;
            }

            SearchResponse response;
            try {
                //Do an initial search request to get the rootDSE
                //This ldap filter is equivalent to (objectclass=*)
                var searchRequest = CreateSearchRequest("", new LDAPFilter().AddAllObjects().GetFilter(),
                    SearchScope.Base, null);

                response = (SearchResponse)connection.SendRequest(searchRequest);
            }
            catch (LdapException e) {
                /*
                 * If we can't send the initial search request, its unlikely any other search requests will work so we will immediately return false
                 */
                testResult.Message = e.Message;
                testResult.ErrorCode = e.ErrorCode;
                return false;
            }

            if (response?.Entries == null || response.Entries.Count == 0) {
                /*
                 * This can happen for one of two reasons, either we dont have permission to query AD or we're authenticating
                 * across external trusts with kerberos authentication without Forest Search Order properly configured.
                 * Either way, this connection isn't useful for us because we're not going to get data, so return false
                 */
            
                connection.Dispose();
                throw new NoLdapDataException();
            }

            testResult.SearchResultEntry = new SearchResultEntryWrapper(response.Entries[0]);
            testResult.Message = "";
            return true;
        }

        private class LdapConnectionTestResult {
            public string Message { get; set; }
            public ISearchResultEntry SearchResultEntry { get; set; }
            public int ErrorCode { get; set; }
        }
    
        private async Task<(bool success, LdapConnectionWrapper connection)> CreateLDAPConnectionWithPortCheck(
            string target, bool globalCatalog) {
            if (globalCatalog) {
                if (await _portScanner.CheckPort(target, _ldapConfig.GetGCPort(true)) || (!_ldapConfig.ForceSSL &&
                        await _portScanner.CheckPort(target, _ldapConfig.GetGCPort(false))))
                    return (CreateLdapConnection(target, true, out var connection), connection);
            }
            else {
                if (await _portScanner.CheckPort(target, _ldapConfig.GetPort(true)) || (!_ldapConfig.ForceSSL &&
                        await _portScanner.CheckPort(target, _ldapConfig.GetPort(false))))
                    return (CreateLdapConnection(target, true, out var connection), connection);
            }

            return (false, null);
        }
    
        private SearchRequest CreateSearchRequest(string distinguishedName, string ldapFilter,
            SearchScope searchScope,
            string[] attributes) {
            var searchRequest = new SearchRequest(distinguishedName, ldapFilter,
                searchScope, attributes);
            searchRequest.Controls.Add(new SearchOptionsControl(SearchOption.DomainScope));
            return searchRequest;
        }
    }
}

//TESTLAB
//TESTLAB.LOCAL
//PRIMARY.TESTLAB.LOCAL