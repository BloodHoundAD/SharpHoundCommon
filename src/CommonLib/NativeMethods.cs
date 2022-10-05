using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging;
using SharpHoundRPC.NetAPINative;

namespace SharpHoundCommonLib
{
    [ExcludeFromCodeCoverage]
    // This class exists entirely as a shim for testing
    public class NativeMethods
    {
        private readonly ILogger _log;

        public NativeMethods(ILogger log = null)
        {
            _log = log ?? Logging.LogProvider.CreateLogger("NativeMethods");
        }

        public NativeMethods()
        {
            _log = Logging.LogProvider.CreateLogger("NativeMethods");
        }

        public virtual NetAPIResult<IEnumerable<NetSessionEnumResults>> NetSessionEnum(string serverName)
        {
            return NetAPIMethods.NetSessionEnum(serverName);
        }

        public virtual NetAPIResult<IEnumerable<NetWkstaUserEnumResults>> NetWkstaUserEnum(string servername)
        {
            return NetAPIMethods.NetWkstaUserEnum(servername);
        }

        public virtual NetAPIResult<NetAPIStructs.DomainControllerInfo> CallDsGetDcName(string computerName,
            string domainName)
        {
            return NetAPIMethods.DsGetDcName(computerName, domainName);
        }
    }
}