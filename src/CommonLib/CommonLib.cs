using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Processors;

namespace SharpHoundCommonLib
{
    public class CommonLib
    {
        private static bool _initialized;
        public static void InitializeCommonLib(LDAPConfig config, ILogger log = null, string cachePath = null)
        {
            if (_initialized)
            {
                Logging.Log(LogLevel.Error, "Common Library is already initialized");
                return;
            }

            _initialized = true;
            if (log != null)
                Logging.ConfigureLogging(log);
            
            LDAPUtils.UpdateLDAPConfig(config);
            
            if (cachePath == null)
                Cache.CreateNewCache();
            else
                Cache.LoadExistingCache(cachePath);
            
            ACLProcessor.BuildGUIDCache();
        }

        public static void ReconfigureLogging(ILogger log)
        {
            Logging.ConfigureLogging(log);
        }
    }
}