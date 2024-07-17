using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Moq;
using System.DirectoryServices.Protocols;
using SharpHoundCommonLib;

public class RangedRetrievalTests
{
    private readonly Mock<ConnectionPoolManager> _mockConnectionPool;
    private readonly LdapUtils _utils;

    public RangedRetrievalTests()
    {
        _mockConnectionPool = new Mock<ConnectionPoolManager>();
        _utils = new LdapUtils();
    }

    // [Fact]
    // public async Task RangedRetrieval_SuccessfulRetrieval_ReturnsExpectedResults()
    // {
    //     // Arrange
    //     var distinguishedName = "CN=TestUser,DC=example,DC=com";
    //     var attributeName = "member";
    //     var domain = "example.com";

    //     var connectionWrapper = new Mock<LdapConnectionWrapper>();
    //     var connection = new Mock<LdapConnection>();
    //     connectionWrapper.SetupGet(x => x.Connection).Returns(connection.Object);
        
    //     _mockConnectionPool.Setup(x => x.GetLdapConnection(domain, false))
    //             .ReturnsAsync((true, connectionWrapper.Object, null));

    //     var searchResponse = new Mock<SearchResponse>();
    //     var entry = new SearchResultEntry
    //     {
    //         Attributes =
    //         {
    //             new DirectoryAttribute("member;range=0-*", "CN=Member1,DC=example,DC=com", "CN=Member2,DC=example,DC=com")
    //         }
    //     };
    //     searchResponse.Entries.Add(entry);

    //     connection.Setup(x => x.SendRequest(It.IsAny<SearchRequest>()))
    //         .Returns(searchResponse);

    //     // Act
    //     var results = new List<Result<string>>();
    //     await foreach (var result in _utils.RangedRetrieval(distinguishedName, attributeName))
    //     {
    //         results.Add(result);
    //     }

    //     // Assert
    //     Assert.Equal(2, results.Count);
    //     Assert.True(results[0].IsSuccess);
    //     Assert.Equal("CN=Member1,DC=example,DC=com", results[0].Value);
    //     Assert.True(results[1].IsSuccess);
    //     Assert.Equal("CN=Member2,DC=example,DC=com", results[1].Value);
    // }

    [Fact]
    public async Task RangedRetrieval_ConnectionFailure_ReturnsFailResult()
    {
        // Arrange
        var distinguishedName = "CN=TestUser,DC=example,DC=com";
        var attributeName = "member";
        var domain = "example.com";

        _mockConnectionPool.Setup(x => x.GetLdapConnection(domain, false))
                .ReturnsAsync((false, null, "Connection failed"));

        // Act
        var results = new List<Result<string>>();
        await foreach (var result in _utils.RangedRetrieval(distinguishedName, attributeName))
        {
            results.Add(result);
        }

        // Assert
        Assert.Single(results);
        Assert.False(results[0].IsSuccess);
        Assert.Equal("Connection failed", results[0].Error);
    }

    // [Fact]
    // public async Task RangedRetrieval_ServerDown_RetriesAndRecovers()
    // {
    //     // Arrange
    //     var distinguishedName = "CN=TestUser,DC=example,DC=com";
    //     var attributeName = "member";
    //     var domain = "example.com";

    //     var connectionWrapper = new Mock<LdapConnectionWrapper>();
    //     var connection = new Mock<LdapConnection>();
        
    //     // TODO : setup

    //     // Act
    //     var results = new List<Result<string>>();
    //     await foreach (var result in _utils.RangedRetrieval(distinguishedName, attributeName))
    //     {
    //         results.Add(result);
    //     }

    //     // TODO Assert
    // }

    [Fact]
    public async Task RangedRetrieval_CancellationRequested_StopsRetrieval()
    {
        // Arrange
        var distinguishedName = "CN=TestUser,DC=example,DC=com";
        var attributeName = "member";
        var domain = "example.com";

        var connectionWrapper = new Mock<LdapConnectionWrapper>();
        var connection = new Mock<LdapConnection>();

        _mockConnectionPool.Setup(x => x.GetLdapConnection(domain, false))
                .ReturnsAsync((true, connectionWrapper.Object, null));

        var cts = new CancellationTokenSource();
        cts.Cancel();

        // Act
        var results = new List<Result<string>>();
        await foreach (var result in _utils.RangedRetrieval(distinguishedName, attributeName, cts.Token))
        {
            results.Add(result);
        }

        // Assert
        Assert.Empty(results);
    }
}