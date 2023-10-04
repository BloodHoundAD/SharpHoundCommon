using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
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

        public ResolvedSearchResult ResolveBloodHoundInfo()
        {
            throw new NotImplementedException();
        }

        public string GetProperty(string propertyName)
        {
            return _properties[propertyName] as string;
        }

        public byte[] GetByteProperty(string propertyName)
        {
            if (!_properties.Contains(propertyName))
                return null;

            if (_properties[propertyName] is string prop)
            {
                return Encoding.ASCII.GetBytes(prop);
            }

            return _properties[propertyName] as byte[];
        }

        public string[] GetArrayProperty(string propertyName)
        {
            if (!_properties.Contains(propertyName))
                return Array.Empty<string>();

            var value = _properties[propertyName];
            if (value.IsArray())
                return value as string[];
            
            return new [] { (value ?? "").ToString() };
        }

        public byte[][] GetByteArrayProperty(string propertyName)
        {
            if (!_properties.Contains(propertyName))
                return Array.Empty<byte[]>();
            
            var property = _properties[propertyName] as byte[][];
            return property;
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
            var property = _properties[prop];
            if (property.IsArray())
            {
                var cast = property as string[];
                return cast?.Length ?? 0;
            }

            return 1;
        }

        public IEnumerable<string> PropertyNames()
        {
            foreach (var property in _properties.Keys) yield return property.ToString().ToLower();
        }

        public bool IsMSA()
        {
            throw new NotImplementedException();
        }

        public bool IsGMSA()
        {
            throw new NotImplementedException();
        }

        public bool HasLAPS()
        {
            throw new NotImplementedException();
        }
    }
}