using System.Security.Cryptography;

namespace SharpHoundCommonLib.OutputTypes
{
    public class CertOid
    {
        public string Name { get; set; }
        public string Value { get; set; }

        public CertOid(Oid oid)
        {
            Name = oid.FriendlyName;
            Value = oid.Value;
        }
    }
}