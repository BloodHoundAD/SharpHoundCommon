using System.Security.Cryptography.X509Certificates;

namespace SharpHoundCommonLib.OutputTypes
{
    public class CertificateExtension
    {
        public CertOid Oid { get; set; }
        public bool Critical { get; set; }

        public CertificateExtension(X509Extension extension)
        {
            Oid = new CertOid(extension.Oid);
            Critical = extension.Critical;
        }
    }
}