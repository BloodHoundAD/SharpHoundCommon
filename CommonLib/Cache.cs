using System.Collections.Concurrent;

namespace CommonLib
{
    public class Cache
    {
        private ConcurrentDictionary<string, string> _valueToSidCache;
        private ConcurrentDictionary<string, string> _sidToTypeCache;
        private ConcurrentDictionary<string, string[]> _globalCatalogCache;
        private BaseCacheProvider _baseCacheProvider;

        internal static Cache Instance => CacheInstance;
        
        private static Cache CacheInstance { get; set; }

        private Cache(BaseCacheProvider baseCacheProvider)
        {
            _baseCacheProvider = baseCacheProvider;
        }

        internal static void CreateInstance(BaseCacheProvider cacheImplementation, bool invalidateCache)
        {
            CacheInstance = new Cache(cacheImplementation);
        }

        private void LoadCache()
        {
            
        }
    }
}