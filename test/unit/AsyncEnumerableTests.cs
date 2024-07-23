using System.Threading.Tasks;
using SharpHoundCommonLib;
using Xunit;

namespace CommonLibTest;

public class AsyncEnumerableTests {
    [Fact]
    public async Task AsyncEnumerable_DefaultIfEmpty_Empty() {
        var enumerable = AsyncEnumerable.Empty<int>().DefaultIfEmpty(1);
        var e = enumerable.GetAsyncEnumerator();
        var res = await e.MoveNextAsync();
        Assert.True(res);
        Assert.Equal(1, e.Current);
        Assert.False(await e.MoveNextAsync());
    }

    [Fact]
    public async Task AsyncEnumerable_FirstOrDefault() {
        var enumerable = AsyncEnumerable.Empty<int>();
        var res = await enumerable.FirstOrDefaultAsync();
        Assert.Equal(0, res);
    }
    
    [Fact]
    public async Task AsyncEnumerable_FirstOrDefault_WithDefault() {
        var enumerable = AsyncEnumerable.Empty<int>();
        var res = await enumerable.FirstOrDefaultAsync(10);
        Assert.Equal(10, res);
    }

    [Fact]
    public async Task AsyncEnumerable_CombinedOperators() {
        var enumerable = AsyncEnumerable.Empty<string>();
        var res = await enumerable.DefaultIfEmpty("abc").FirstOrDefaultAsync();
        Assert.Equal("abc", res);
    }
}