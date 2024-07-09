using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Moq;
using System.DirectoryServices.Protocols;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;

public class RangedRetrievalTests
{
    private readonly Mock<ConnectionPoolManager> _mockConnectionPool;
    private readonly LdapUtils _utils;

    public RangedRetrievalTests()
    {
        _mockConnectionPool = new Mock<ConnectionPoolManager>();
        _utils = new LdapUtils();
    }

    [Fact]
    public async Task RangedRetrieval_SuccessfulRetrieval_ReturnsExpectedResults()
    {
        // Arrange
        var distinguishedName = "CN=TestUser,DC=example,DC=com";
        var attributeName = "member";
        var domain = "example.com";

        var connectionWrapper = new Mock<LdapConnectionWrapper>();
        var connection = new Mock<LdapConnection>();
        
        // TODO : setup

        // Act
        var results = new List<Result<string>>();
        await foreach (var result in _utils.RangedRetrieval(distinguishedName, attributeName))
        {
            results.Add(result);
        }

        // TODO : Assert
        
    }

    [Fact]
    public async Task RangedRetrieval_ConnectionFailure_ReturnsFailResult()
    {
        // Arrange
        var distinguishedName = "CN=TestUser,DC=example,DC=com";
        var attributeName = "member";
        var domain = "example.com";

        var connectionWrapper = new Mock<LdapConnectionWrapper>();
        var connection = new Mock<LdapConnection>();
        
        // TODO : setup

        // Act
        var results = new List<Result<string>>();
        await foreach (var result in _utils.RangedRetrieval(distinguishedName, attributeName))
        {
            results.Add(result);
        }

        // TODO : Assert
    }

    [Fact]
    public async Task RangedRetrieval_ServerDown_RetriesAndRecovers()
    {
        // Arrange
        var distinguishedName = "CN=TestUser,DC=example,DC=com";
        var attributeName = "member";
        var domain = "example.com";

        var connectionWrapper = new Mock<LdapConnectionWrapper>();
        var connection = new Mock<LdapConnection>();
        
        // TODO : setup

        // Act
        var results = new List<Result<string>>();
        await foreach (var result in _utils.RangedRetrieval(distinguishedName, attributeName))
        {
            results.Add(result);
        }

        // TODO Assert
    }

    [Fact]
    public async Task RangedRetrieval_CancellationRequested_StopsRetrieval()
    {
        // Arrange
        var distinguishedName = "CN=TestUser,DC=example,DC=com";
        var attributeName = "member";
        var domain = "example.com";

        var connectionWrapper = new Mock<LdapConnectionWrapper>();
        var connection = new Mock<LdapConnection>();

        // TODO : setup

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