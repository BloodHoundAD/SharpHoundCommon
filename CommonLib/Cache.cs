using System;
using System.Collections.Concurrent;
using System.IO;
using System.Reflection;
using System.Text;
using Newtonsoft.Json;

namespace CommonLib
{
    public class Cache
    {
        private readonly ConcurrentDictionary<string, string> _valueToSidCache;
        private readonly ConcurrentDictionary<string, string> _sidToTypeCache;
        private readonly ConcurrentDictionary<string, string[]> _globalCatalogCache;
        private readonly ConcurrentDictionary<string, string> _machineSidCache;
        private string fileName;

        internal static Cache Instance => CacheInstance;
        
        private static Cache CacheInstance { get; set; }
        
        private Cache()
        {
            _valueToSidCache = new ConcurrentDictionary<string, string>();
            _sidToTypeCache = new ConcurrentDictionary<string, string>();
            _globalCatalogCache = new ConcurrentDictionary<string, string[]>();
            _machineSidCache = new ConcurrentDictionary<string, string>();
        }

        internal static void AddMachineSid(string key, string value)
        {
            CacheInstance?._machineSidCache.TryAdd(key, value);
        }

        internal static bool GetMachineSid(string key, out string value)
        {
            if (CacheInstance != null) return CacheInstance._machineSidCache.TryGetValue(key, out value);
            value = null;
            return false;
        }

        internal static void AddConvertedValue(string key, string value)
        {
            CacheInstance?._valueToSidCache.TryAdd(key, value);
        }

        internal void AddPrefixedValue(string key, string domain, string value)
        {
            CacheInstance?._valueToSidCache.TryAdd(GetPrefixKey(key, domain), value);
        }

        internal void AddType(string key, string value)
        {
            CacheInstance?._sidToTypeCache.TryAdd(key, value);
        }

        internal void AddGCCache(string key, string[] value)
        {
            _globalCatalogCache?.TryAdd(key, value);
        }

        internal bool GetGCCache(string key, out string[] value)
        {
            if (_globalCatalogCache != null) return _globalCatalogCache.TryGetValue(key, out value);
            value = null;
            return false;
        }

        internal bool GetConvertedValue(string key, out string value)
        {
            if (_valueToSidCache != null) return _valueToSidCache.TryGetValue(key, out value);
            value = null;
            return false;
        }
        
        internal bool GetPrefixedValue(string key, string domain, out string value)
        {
            if (_valueToSidCache != null) return _valueToSidCache.TryGetValue(GetPrefixKey(key, domain), out value);
            value = null;
            return false;
        }

        internal bool GetSidType(string key, out string value)
        {
            if (_sidToTypeCache != null) return _sidToTypeCache.TryGetValue(key, out value);
            value = null;
            return false;

        }

        private static string GetPrefixKey(string key, string domain)
        {
            return $"{key}|{domain}";
        }
        
        public static void CreateNewCache()
        {
            CacheInstance = new Cache();
        }

        public static void LoadExistingCache(string filePath)
        {
            if (!File.Exists(filePath))
            {
                CacheInstance = new Cache();
                Logging.Log("Cache file not found, empty cache created.");
                return;
            }

            try
            {
                var bytes = File.ReadAllBytes(filePath);
                var json = new UTF8Encoding(true).GetString(bytes);
                CacheInstance = JsonConvert.DeserializeObject<Cache>(json);
                Logging.Log(
                    $"Cache file loaded! Loaded {CacheInstance._sidToTypeCache.Count} SID to type mappings and {CacheInstance._valueToSidCache.Count} name to SID mappings.");
            }
            catch (Exception e)
            {
                Logging.Log($"Exception loading cache: {e}. Creating empty cache.");
                CacheInstance = new Cache();
            }
        }

        public static void SaveCache(string filePath)
        {
            var serialized = new UTF8Encoding(true).GetBytes(JsonConvert.SerializeObject(CacheInstance));
            using var stream = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None);
            stream.Write(serialized, 0, serialized.Length);
        }
    }
}