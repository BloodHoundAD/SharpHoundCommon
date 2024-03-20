using System.Collections.Generic;
using CommonLibTest.Facades;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using Xunit;

namespace CommonLibTest
{
    public class SearchResultEntryTests
    {
        [Fact]
        public void GetLabelTests()
        {
            var attribs = new Dictionary<string, string>
            {
                { "objectsid", "abc123"},
                { "objectclass", "msPKI-Enterprise-Oid" }
            };

            var sre = MockableSearchResultEntry.Construct(attribs, "abc");
            Assert.Equal(Label.IssuancePolicy, sre.GetLabel());
        }
    }
}