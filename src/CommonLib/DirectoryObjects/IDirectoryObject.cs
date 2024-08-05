using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace SharpHoundCommonLib;

public interface IDirectoryObject {
    bool TryGetDistinguishedName(out string value);
    bool TryGetProperty(string propertyName, out string value);
    bool TryGetByteProperty(string propertyName, out byte[] value);
    bool TryGetArrayProperty(string propertyName, out string[] value);
    bool TryGetByteArrayProperty(string propertyName, out byte[][] value);
    bool TryGetLongProperty(string propertyName, out long value);
    bool TryGetCertificateArrayProperty(string propertyName, out X509Certificate2[] value);
    bool TryGetSecurityIdentifier(out string securityIdentifier);
    bool TryGetGuid(out string guid);
    string GetProperty(string propertyName);
    byte[] GetByteProperty(string propertyName);
    int PropertyCount(string propertyName);
    IEnumerable<string> PropertyNames();
}