using CommonLib.Processors;
using Microsoft.Extensions.Logging;

namespace CommonLib
{
    public class CommonLib
    {
        public static void InitializeCommonLib(LDAPConfig config, ILogger log = null, string cachePath = null)
        {
            LDAPUtils.UpdateLDAPConfig(config);
            if (log != null)
                Logging.ConfigureLogging(log);
            
            if (cachePath == null)
                Cache.CreateNewCache();
            else
                Cache.LoadExistingCache(cachePath);
            
            ACLProcessor.BuildGUIDCache();
        }
    }
}