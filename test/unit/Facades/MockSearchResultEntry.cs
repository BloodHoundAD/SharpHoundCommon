using System.Collections;
using System.Collections.Generic;
using System.Threading.Tasks;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;

namespace CommonLibTest.Facades
{
    public class MockSearchResultEntry : ISearchResultEntry
    {
        private readonly IDictionary _properties;
        private readonly string _objectId;
        private readonly Label _objectType;

        public MockSearchResultEntry(string distinguishedName, IDictionary properties, string objectId, Label objectType)
        {
            DistinguishedName = distinguishedName;
            _properties = properties;
            _objectId = objectId;
            _objectType = objectType;
        }

        public string DistinguishedName { get; }

        public Task<ResolvedSearchResult> ResolveBloodHoundInfo()
        {
            throw new System.NotImplementedException();
        }

        public string GetProperty(string propertyName)
        {
            throw new System.NotImplementedException();
        }

        public byte[] GetByteProperty(string propertyName)
        {
            throw new System.NotImplementedException();
        }

        public string[] GetArrayProperty(string propertyName)
        {
            throw new System.NotImplementedException();
        }

        public byte[][] GetByteArrayProperty(string propertyName)
        {
            throw new System.NotImplementedException();
        }

        public string GetObjectIdentifier()
        {
            return _objectId;
        }

        public bool IsDeleted()
        {
            throw new System.NotImplementedException();
        }

        public Label GetLabel()
        {
            return _objectType;
        }

        public string GetSid()
        {
            return _objectId;
        }

        public string GetGuid()
        {
            return _objectId;
        }

        public int PropCount(string prop)
        {
            throw new System.NotImplementedException();
        }

        public IEnumerable<string> PropertyNames()
        {
            throw new System.NotImplementedException();
        }
    }
}