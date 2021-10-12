using Microsoft.Extensions.Logging;

namespace SharpHoundCommonLib
{
    public class CommonLib
    {
        private static bool _initialized;

        public static void InitializeCommonLib(ILogger log = null, Cache cache = null)
        {
            if (_initialized)
            {
                Logging.Log(LogLevel.Error, "Common Library is already initialized");
                return;
            }

            _initialized = true;
            if (log != null)
                Logging.ConfigureLogging(log);

            if (cache == null)
                Cache.CreateNewCache();
            else
                Cache.SetCacheInstance(cache);
        }

        public static void ReconfigureLogging(ILogger log)
        {
            Logging.ConfigureLogging(log);
        }
    }
}