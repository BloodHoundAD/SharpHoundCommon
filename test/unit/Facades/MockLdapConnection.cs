using System;
using System.DirectoryServices.Protocols;
using Moq;

namespace CommonLibTest.Facades
{
    public static class MockLdapConnection
    {
        public static LdapConnection Get(ResponseBehavior responseBehavior)
            => responseBehavior switch
        {
            ResponseBehavior.HappyPath => HappyPathResponse(),
            ResponseBehavior.NullResponse => ReturnsNullResponse(),
            ResponseBehavior.EmptyResponse => ReturnsEmptyResponse(),
            ResponseBehavior.ThrowsLdapException => ThrowsLdapException(),
            _ => throw new ArgumentOutOfRangeException(nameof(responseBehavior))
        };

        private static LdapConnection HappyPathResponse()
        {
            // Create a mock SearchResultEntry
            var entryMock = new Mock<SearchResultEntry>("DN=MockEntry,DC=example,DC=com");
            // Add attributes to the entry if needed
            entryMock.SetupGet(e => e.Attributes["cn"]).Returns(new DirectoryAttribute("MockEntry"));

            // TODO : add properties to entryMock as used by TestConnection

            // Create a mock SearchResultEntryCollection
            var entryCollectionMock = new Mock<SearchResultEntryCollection>();
            entryCollectionMock.Setup(e => e.GetEnumerator()).Returns(new[] { entryMock.Object }.GetEnumerator());
            entryCollectionMock.SetupGet(e => e.Count).Returns(1);

            // Create a mock SearchResponse
            var searchResponseMock = new Mock<SearchResponse>();
            searchResponseMock.SetupGet(r => r.Entries).Returns(entryCollectionMock.Object);

            // Modify searchResponseMock to return entryMock when accessing Entries[]
            searchResponseMock.SetupGet(r => r.Entries[It.IsAny<int>()]).Returns(entryMock.Object);
            
            var connectionMock = new Mock<LdapConnection>();
            connectionMock.Setup(x => x.SendRequest(It.IsAny<SearchRequest>()))
                .Returns(searchResponseMock.Object);
            return connectionMock.Object;
        }

        private static LdapConnection ReturnsNullResponse()
        {
            var mock = new Mock<LdapConnection>();
            mock.Setup(x => x.SendRequest(It.IsAny<SearchRequest>()))
                .Returns<SearchResponse>(null);
            return mock.Object;
        }

        private static LdapConnection ReturnsEmptyResponse()
        {
            var mock = new Mock<LdapConnection>();
            var emptyResponseMock = Mock.Of<SearchResponse>(m => m.Entries == Mock.Of<SearchResultEntryCollection>(m => m.Count == 0));
            mock.Setup(x => x.SendRequest(It.IsAny<SearchRequest>()))
                .Returns(emptyResponseMock);
            return mock.Object;
        }

        private static LdapConnection ThrowsLdapException()
        {
            var mock = new Mock<LdapConnection>();
            mock.Setup(x => x.SendRequest(It.IsAny<SearchRequest>()))
                .Throws<LdapException>();
            return mock.Object;
        }
    }

    public enum ResponseBehavior
    {
        HappyPath,
        NullResponse,
        EmptyResponse,
        ThrowsLdapException,
    }
}