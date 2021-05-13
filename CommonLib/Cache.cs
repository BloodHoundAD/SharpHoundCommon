using System;
using System.Collections.Concurrent;
using System.IO;
using System.Text;
using Newtonsoft.Json;
using SharpHoundCommonLib.Enums;

namespace SharpHoundCommonLib
{
    public class Cache
    {
        private readonly ConcurrentDictionary<string, string> _valueToIDCache;
        private readonly ConcurrentDictionary<string, Label> _idToTypeCache;
        private readonly ConcurrentDictionary<string, string[]> _globalCatalogCache;
        private readonly ConcurrentDictionary<string, string> _machineSidCache;
        private readonly ConcurrentDictionary<string, string> _sidToDomainCache;

        internal static Cache Instance => CacheInstance;
        
        private static Cache CacheInstance { get; set; }
        
        private Cache()
        {
            _valueToIDCache = new ConcurrentDictionary<string, string>();
            _idToTypeCache = new ConcurrentDictionary<string, Label>();
            _globalCatalogCache = new ConcurrentDictionary<string, string[]>();
            _machineSidCache = new ConcurrentDictionary<string, string>();
            _sidToDomainCache = new ConcurrentDictionary<string, string>();
        }

        internal static void AddSidToDomain(string key, string value)
        {
            CacheInstance?._sidToDomainCache.TryAdd(key, value);
        }

        internal static bool GetDomainSidMapping(string key, out string value)
        {
            if (CacheInstance != null) return CacheInstance._machineSidCache.TryGetValue(key, out value);
            value = null;
            return false;
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
            CacheInstance?._valueToIDCache.TryAdd(key, value);
        }

        internal static void AddPrefixedValue(string key, string domain, string value)
        {
            CacheInstance?._valueToIDCache.TryAdd(GetPrefixKey(key, domain), value);
        }

        internal static void AddType(string key, Label value)
        {
            CacheInstance?._idToTypeCache.TryAdd(key, value);
        }

        internal static void AddGCCache(string key, string[] value)
        {
            CacheInstance?._globalCatalogCache?.TryAdd(key, value);
        }

        internal static bool GetGCCache(string key, out string[] value)
        {
            if (CacheInstance != null) return CacheInstance._globalCatalogCache.TryGetValue(key, out value);
            value = null;
            return false;
        }

        internal static bool GetConvertedValue(string key, out string value)
        {
            if (CacheInstance != null) return CacheInstance._valueToIDCache.TryGetValue(key, out value);
            value = null;
            return false;
        }
        
        internal static bool GetPrefixedValue(string key, string domain, out string value)
        {
            if (CacheInstance != null) return CacheInstance._valueToIDCache.TryGetValue(GetPrefixKey(key, domain), out value);
            value = null;
            return false;
        }

        internal static bool GetIDType(string key, out Label value)
        {
            if (CacheInstance != null) return CacheInstance._idToTypeCache.TryGetValue(key, out value);
            value = Label.Unknown;
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
                    $"Cache file loaded! Loaded {CacheInstance._idToTypeCache.Count} SID to type mappings and {CacheInstance._valueToIDCache.Count} name to SID mappings.");
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