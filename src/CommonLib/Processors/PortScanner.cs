using System.Net.Sockets;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace SharpHoundCommonLib.Processors
{
    public class PortScanner
    {
        private readonly ILogger _log;

        public PortScanner(ILogger log = null)
        {
            _log = log ?? Logging.LogProvider.CreateLogger("PortScanner");
        }

        /// <summary>
        ///     Checks if a specified port is open on a host. Defaults to 445 (SMB)
        /// </summary>
        /// <param name="hostname"></param>
        /// <param name="port"></param>
        /// <param name="timeout">Timeout in milliseconds</param>
        /// <returns>True if port is open, otherwise false</returns>
        public virtual async Task<bool> CheckPort(string hostname, int port = 445, int timeout = 500)
        {
            try
            {
                using var client = new TcpClient();
                var ca = client.ConnectAsync(hostname, port);
                await Task.WhenAny(ca, Task.Delay(timeout));
                client.Close();
                if (!ca.IsFaulted && ca.IsCompleted) return true;
                _log.LogDebug("{hostname} did not respond to ping", hostname);
                return false;
            }
            catch
            {
                return false;
            }
        }
    }
}