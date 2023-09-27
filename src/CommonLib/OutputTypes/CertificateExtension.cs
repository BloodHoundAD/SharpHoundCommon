using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SharpHoundCommonLib.OutputTypes
{
    public class CertificateExtension
    {
        public Oid Oid { get; set; }
        public bool Critical { get; set; }

        public CertificateExtension(X509Extension extension)
        {
            Oid = new Oid(extension.Oid);
            Critical = extension.Critical;
        }
    }
}