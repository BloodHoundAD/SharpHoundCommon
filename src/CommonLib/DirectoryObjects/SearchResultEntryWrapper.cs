using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Runtime.Serialization;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;

namespace SharpHoundCommonLib;
[DataContract]
public class SearchResultEntryWrapper : IDirectoryObject {
    [DataMember]
    private readonly SearchResultEntry _entry;

    public SearchResultEntryWrapper(SearchResultEntry entry) {
        _entry = entry;
    }

    public bool TryGetDistinguishedName(out string value) {
        return TryGetProperty(LDAPProperties.DistinguishedName, out value) && !string.IsNullOrWhiteSpace(value);
    }

    public bool TryGetProperty(string propertyName, out string value) {
        value = string.Empty;
        if (!_entry.Attributes.Contains(propertyName))
            return false;

        var collection = _entry.Attributes[propertyName];
        //Use GetValues to auto-convert to the proper type
        var lookups = collection.GetValues(typeof(string));
        if (lookups.Length == 0)
            return false;

        if (lookups[0] is not string prop || prop.Length == 0)
            return false;

        value = prop;
        return true;
    }

    public bool TryGetByteProperty(string propertyName, out byte[] value) {
        value = Array.Empty<byte>();
        if (!_entry.Attributes.Contains(propertyName))
            return false;

        var collection = _entry.Attributes[propertyName];
        var lookups = collection.GetValues(typeof(byte[]));

        if (lookups.Length == 0)
            return false;

        if (lookups[0] is not byte[] bytes || bytes.Length == 0)
            return false;

        value = bytes;
        return true;
    }

    public bool TryGetArrayProperty(string propertyName, out string[] value) {
        value = Array.Empty<string>();
        if (!_entry.Attributes.Contains(propertyName))
            return false;

        var values = _entry.Attributes[propertyName];
        var strings = values.GetValues(typeof(string));

        if (strings.Length == 0) return true;
        if (strings is not string[] result) return false;

        value = result;
        return true;
    }

    public bool TryGetByteArrayProperty(string propertyName, out byte[][] value) {
        value = Array.Empty<byte[]>();
        if (!_entry.Attributes.Contains(propertyName))
            return false;

        var values = _entry.Attributes[propertyName];
        var bytes = values.GetValues(typeof(byte[]));

        if (bytes is not byte[][] result) return false;
        value = result;
        return true;
    }

    public bool TryGetLongProperty(string propertyName, out long value) {
        if (!TryGetProperty(propertyName, out var raw)) {
            value = 0;
            return false;
        }
        
        return long.TryParse(raw, out value);
    }

    public bool TryGetCertificateArrayProperty(string propertyName, out X509Certificate2[] value) {
        value = Array.Empty<X509Certificate2>();

        if (!TryGetByteArrayProperty(propertyName, out var bytes)) {
            return false;
        }

        if (bytes.Length == 0) {
            return true;
        }

        var result = new List<X509Certificate2>();

        foreach (var b in bytes) {
            try {
                var cert = new X509Certificate2(b);
                result.Add(cert);
            } catch {
                //pass
            }
        }

        value = result.ToArray();
        return true;
    }

    public bool TryGetSecurityIdentifier(out string securityIdentifier) {
        securityIdentifier = string.Empty;
        if (!_entry.Attributes.Contains(LDAPProperties.ObjectSID)) return false;

        object[] s;
        try {
            s = _entry.Attributes[LDAPProperties.ObjectSID].GetValues(typeof(byte[]));
        } catch (NotSupportedException) {
            return false;
        }

        if (s.Length == 0)
            return false;

        if (s[0] is not byte[] sidBytes || sidBytes.Length == 0)
            return false;

        try {
            var sid = new SecurityIdentifier(sidBytes, 0);
            securityIdentifier = sid.Value.ToUpper();
            return true;
        } catch {
            return false;
        }
    }

    public bool TryGetGuid(out string guid) {
        guid = string.Empty;
        if (!TryGetByteProperty(LDAPProperties.ObjectGUID, out var raw)) {
            return false;
        }

        try {
            guid = new Guid(raw).ToString().ToUpper();
            return true;
        } catch {
            return false;
        }
    }

    public string GetProperty(string propertyName) {
        if (!_entry.Attributes.Contains(propertyName))
            return null;

        var collection = _entry.Attributes[propertyName];
        //Use GetValues to auto-convert to the proper type
        var lookups = collection.GetValues(typeof(string));
        if (lookups.Length == 0)
            return null;

        if (lookups[0] is not string prop || prop.Length == 0)
            return null;

        return prop;
    }

    public byte[] GetByteProperty(string propertyName) {
        if (!_entry.Attributes.Contains(propertyName))
            return null;

        var collection = _entry.Attributes[propertyName];
        var lookups = collection.GetValues(typeof(byte[]));

        if (lookups.Length == 0)
            return Array.Empty<byte>();

        if (lookups[0] is not byte[] bytes || bytes.Length == 0)
            return Array.Empty<byte>();

        return bytes;
    }

    public int PropertyCount(string propertyName) {
        if (!_entry.Attributes.Contains(propertyName)) return 0;
        var prop = _entry.Attributes[propertyName];
        return prop.Count;
    }

    public IEnumerable<string> PropertyNames() {
        if (_entry.Attributes.AttributeNames != null)
            foreach (var property in _entry.Attributes.AttributeNames)
                yield return property.ToString().ToLower();
    }
}