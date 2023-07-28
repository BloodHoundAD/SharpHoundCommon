using System;
using Newtonsoft.Json;
using SharpHoundCommonLib;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest;

public class CacheTest
{
    private ITestOutputHelper _testOutputHelper;
    public CacheTest(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
    }
    
    [Fact]
    public void Cache_TestCacheInvalidation()
    {
        var cache = Cache.CreateNewCache();
        var version = new Version(1, 0, 0);
        cache.CacheCreationVersion = version;
        
        Assert.True(Cache.CacheNeedsInvalidation(cache, new Version(1,0,1)));
        Assert.False(Cache.CacheNeedsInvalidation(cache, new Version(1,0,0)));

        var time = DateTime.Now.Subtract(TimeSpan.FromDays(29));
        cache.CacheCreationDate = time;
        Assert.False(Cache.CacheNeedsInvalidation(cache, version));
        cache.CacheCreationDate = DateTime.Now.Subtract(TimeSpan.FromDays(31));
        Assert.True(Cache.CacheNeedsInvalidation(cache, version));
    }

    [Fact]
    public void Cache_TestNewCache()
    {
        var cache = Cache.CreateNewCache();
        Assert.Equal(cache.CacheCreationVersion, new Version(1,0,0));
        var version = new Version(1, 0, 1);
        cache = Cache.CreateNewCache(version);
        var time = DateTime.Now.Date;
        Assert.Equal(cache.CacheCreationVersion, version);
        Assert.Equal(cache.CacheCreationDate, time);
    }

    [Fact]
    public void Cache_OldCacheWillInvalidate()
    {
        const string json = """{"GlobalCatalogCache": {}, "IdToTypeCache": {}, "MachineSidCache": {}, SIDToDomainCache: {}, "ValueToIdCache": {}}""";
        var cache = JsonConvert.DeserializeObject<Cache>(json);
        Assert.Null(cache.CacheCreationVersion);
        Assert.True(Cache.CacheNeedsInvalidation(cache, new Version(1,0,0)));
    }
}