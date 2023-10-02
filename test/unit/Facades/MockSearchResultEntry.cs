using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
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
            //returning something not null specifically for these properties for the parseAllProperties tests
            if (propertyName == "badpasswordtime" || propertyName == "domainsid") return new byte[] { 0x20 };
            return _properties[propertyName] as byte[];
        }

        public string[] GetArrayProperty(string propertyName)
        {
            if (!_properties.Contains(propertyName))
                return Array.Empty<string>();

            var value = _properties[propertyName];
            Type valueType = value.GetType();

            if (valueType.IsArray)
                return value as string[];
            else
                return new string[1] { (value ?? "").ToString() };
        }

        public byte[][] GetByteArrayProperty(string propertyName)
        {

            if (!_properties.Contains(propertyName))
                return Array.Empty<byte[]>();

            var byteArray = new byte[] { 0x20 };
            var byteArrayArray = new byte[][] { byteArray };

            return byteArrayArray;
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
            var count = 0;

            foreach (var property in _properties) count++;

            return count;
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