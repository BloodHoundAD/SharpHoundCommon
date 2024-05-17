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
            ResponseBehavior.NullResponse => ReturnsNullResponse(),
            ResponseBehavior.EmptyResponse => ReturnsEmptyResponse(),
            ResponseBehavior.ThrowsLdapException => ThrowsLdapException(),
            _ => throw new ArgumentOutOfRangeException(nameof(responseBehavior))
        };

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
        NullResponse,
        EmptyResponse,
        ThrowsLdapException,
    }
}