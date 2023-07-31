using System;
using Newtonsoft.Json;
using SharpHoundCommonLib;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest
{
    public class CacheTest
    {
        private ITestOutputHelper _testOutputHelper;
        public CacheTest(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
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
    }
}
