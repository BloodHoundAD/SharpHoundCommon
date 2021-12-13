using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace SharpHoundCommonLib.Processors
{
    public class PortScanner
    {
        private readonly ILogger _log;
        private static readonly ConcurrentDictionary<PingCacheKey, bool> PingCache = new();

        public PortScanner()
        {
            _log = Logging.LogProvider.CreateLogger("PortScanner");
        }
        
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
            var key = new PingCacheKey
            {
                Port = port,
                HostName = hostname
            };

            if (PingCache.TryGetValue(key, out var status))
            {
                _log.LogTrace("Ping cache hit for {HostName} on {Port}: {Status}", hostname, port, status);
                return status;
            }
            
            try
            {
                using var client = new TcpClient();
                var ca = client.ConnectAsync(hostname, port);
                await Task.WhenAny(ca, Task.Delay(timeout));
                client.Close();
                if (!ca.IsFaulted && ca.IsCompleted)
                {
                    PingCache.TryAdd(key, true);
                    return true;
                }
                
                _log.LogDebug("{Hostname} did not respond to ping", hostname);
                PingCache.TryAdd(key, false);
                return false;
            }
            catch
            {
                PingCache.TryAdd(key, false);
                return false;
            }
        }

        public static void ClearCache()
        {
            PingCache.Clear();
        }
        
        private class PingCacheKey
        {
            internal string HostName { get; set; }
            internal int Port { get; set; }

            protected bool Equals(PingCacheKey other)
            {
                return HostName == other.HostName && Port == other.Port;
            }

            public override bool Equals(object obj)
            {
                if (ReferenceEquals(null, obj)) return false;
                if (ReferenceEquals(this, obj)) return true;
                if (obj.GetType() != this.GetType()) return false;
                return Equals((PingCacheKey)obj);
            }

            public override int GetHashCode()
            {
                unchecked
                {
                    return (HostName.GetHashCode() * 397) ^ Port;
                }
            }
        }
    }
}