using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;

namespace CommonLibTest.Facades;

public class MockDirectoryObject : IDirectoryObject {
    private readonly string _objectSID;
    private readonly string _objectGuid;
    private readonly Label _objectType;
    private readonly IDictionary _properties;
    private readonly string _distinguishedName;

    public MockDirectoryObject(string distinguishedName, IDictionary properties, string sid, string guid, Label type) {
        _distinguishedName = distinguishedName;
        _properties = properties;
        _objectSID = sid;
        _objectGuid = guid;
        _objectType = type;
    }
    
    public bool TryGetDistinguishedName(out string value) {
        value = _distinguishedName;
        return true;
    }

    public bool TryGetProperty(string propertyName, out string value) {
        if (!_properties.Contains(propertyName)) {
            value = default;
            return false;
        }

        value = _properties[propertyName] as string;
        return true;
    }

    public bool TryGetByteProperty(string propertyName, out byte[] value) {
        if (!_properties.Contains(propertyName)) {
            value = default;
            return false;
        }

        switch (_properties[propertyName]) {
            case string prop:
                value = Encoding.ASCII.GetBytes(prop);
                return true;
            case byte[] b:
                value = b;
                return true;
            default:
                value = default;
                return false;
        }
    }

    public bool TryGetArrayProperty(string propertyName, out string[] value) {
        if (!_properties.Contains(propertyName)) {
            value = Array.Empty<string>();
            return false;
        }

        var temp = _properties[propertyName];
        if (temp.IsArray()) {
            value = temp as string[];
            return true;
        }

        value = Array.Empty<string>();
        return false;
    }

    public bool TryGetByteArrayProperty(string propertyName, out byte[][] value) {
        if (!_properties.Contains(propertyName)) {
            value = Array.Empty<byte[]>();
            return false;
        }

        if (_properties[propertyName] is byte[][] b) {
            value = b;
            return true;
        }

        value = default;
        return false;
    }

    public bool TryGetIntProperty(string propertyName, out int value) {
        if (!_properties.Contains(propertyName)) {
            value = default;
            return false;
        }

        switch (_properties[propertyName]) {
            case int i:
                value = i;
                return true;
            case string s when int.TryParse(s, out var val):
                value = val;
                return true;
            default:
                value = 0;
                return false;
        }
    }

    public bool TryGetCertificateArrayProperty(string propertyName, out X509Certificate2[] value) {
        if (!TryGetByteArrayProperty(propertyName, out var b)) {
            value = Array.Empty<X509Certificate2>();
            return false;
        }
        
        value = b.Select(x => new X509Certificate2(x)).ToArray();
        return true;
    }

    public bool TryGetSecurityIdentifier(out string securityIdentifier) {
        securityIdentifier = _objectSID;
        return true;
    }

    public bool TryGetGuid(out string guid) {
        guid = _objectGuid;
        return true;
    }

    public string GetProperty(string propertyName) {
        return _properties[propertyName] as string;
    }

    public byte[] GetByteProperty(string propertyName) {
        return _properties[propertyName] as byte[];
    }

    public int PropertyCount(string propertyName) {
        if (!_properties.Contains(propertyName)) {
            return 0;
        }
        
        var property = _properties[propertyName];
        if (property.IsArray())
        {
            var cast = property as string[];
            return cast?.Length ?? 0;
        }

        return 1;
    }

    public IEnumerable<string> PropertyNames() {
        foreach (var property in _properties.Keys) yield return property.ToString().ToLower();
    }
}