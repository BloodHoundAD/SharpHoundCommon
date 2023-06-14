using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using SharpHoundCommonLib.Enums;

namespace SharpHoundCommonLib.OutputTypes
{
    public class Certificate
    {

        public string Thumbprint { get; set; }
        public string Name { get; set; }
        public string[] Chain { get; set; } = Array.Empty<string>();
        public bool HasBasicConstraints { get; set; } = false;
        public int BasicConstraintPathLength { get; set; }
        public CertOid[] EnhancedKeyUsageOids { get; set; }

        public CertificateExtension[] CertificateExtensions { get; set; }

        public Certificate(byte[] rawCertificate)
        {
            var parsedCertificate = new X509Certificate2(rawCertificate);
            Thumbprint = parsedCertificate.Thumbprint;
            var name = parsedCertificate.FriendlyName;
            Name = string.IsNullOrEmpty(name) ? Thumbprint : name;

            // Chain
            var chain = new X509Chain();
            if (!chain.Build(parsedCertificate)) return;
            var temp = new List<string>();
            foreach (var cert in chain.ChainElements) temp.Add(cert.Certificate.Thumbprint);
            Chain = temp.ToArray();

            // Extensions
            X509ExtensionCollection extensions = parsedCertificate.Extensions;
            List<CertificateExtension> certificateExtensions = new List<CertificateExtension>();
            foreach (X509Extension extension in extensions)
            {
                CertificateExtension certificateExtension = new CertificateExtension(extension);
                certificateExtensions.Add(certificateExtension);

                switch (certificateExtension.Oid.Value)
                {
                    case CAExtensionTypes.BasicConstraints:
                        X509BasicConstraintsExtension ext = (X509BasicConstraintsExtension) extension;
                        HasBasicConstraints = ext.HasPathLengthConstraint;
                        BasicConstraintPathLength = ext.PathLengthConstraint;
                        break;

                    case CAExtensionTypes.EnhancedKeyUsage:
                        X509EnhancedKeyUsageExtension extEKU = (X509EnhancedKeyUsageExtension) extension;
                        List<CertOid> enhancedKeyUsageOids = new List<CertOid>();
                        foreach (var oid in extEKU.EnhancedKeyUsages){
                            enhancedKeyUsageOids.Add(new CertOid(oid));
                        }
                        EnhancedKeyUsageOids = enhancedKeyUsageOids.ToArray();
                        break;

                }
            }

            CertificateExtensions = certificateExtensions.ToArray();
        }

    }
}