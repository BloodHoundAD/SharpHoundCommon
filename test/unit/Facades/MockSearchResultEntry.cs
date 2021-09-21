using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;

namespace CommonLibTest.Facades
{
    public class MockSearchResultEntry : ISearchResultEntry
    {
        private readonly string _objectId;
        private readonly Label _objectType;
        private readonly IDictionary _properties;

        public MockSearchResultEntry(string distinguishedName, IDictionary properties, string objectId,
            Label objectType)
        {
            DistinguishedName = distinguishedName;
            _properties = properties;
            _objectId = objectId;
            _objectType = objectType;
        }

        public string DistinguishedName { get; }

        public Task<ResolvedSearchResult> ResolveBloodHoundInfo()
        {
            throw new NotImplementedException();
        }

        public string GetProperty(string propertyName)
        {
            return _properties[propertyName] as string;
        }

        public byte[] GetByteProperty(string propertyName)
        {
            return _properties[propertyName] as byte[];
        }

        public string[] GetArrayProperty(string propertyName)
        {
            return _properties[propertyName] as string[];
        }

        public byte[][] GetByteArrayProperty(string propertyName)
        {
            return _properties[propertyName] as byte[][];
        }

        public bool GetIntProperty(string propertyName, out int value)
        {
            value = _properties[propertyName] is int ? (int)_properties[propertyName] : 0;
            return true;
        }

        public X509Certificate2[] GetCertificateArrayProperty(string propertyName)
        {
            return GetByteArrayProperty(propertyName).Select(x => new X509Certificate2(x)).ToArray();
        }

        public string GetObjectIdentifier()
        {
            return _objectId;
        }

        public bool IsDeleted()
        {
            throw new NotImplementedException();
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
            throw new NotImplementedException();
        }

        public IEnumerable<string> PropertyNames()
        {
            throw new NotImplementedException();
        }
    }
}