using System;
using System.Collections;

namespace CommonLibTest.Facades
{
    public interface ISearchResultEntry : IDisposable
    {
        IDictionary Attributes { get; }
    }
    
    public class MockableSearchResultEntry : ISearchResultEntry
    {
        public string DistinguishedName { get; set; }
        public IDictionary Attributes { get; }

        public void Dispose()
        {
        }
    }
}