using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace SharpHoundCommonLib.OutputTypes
{
    public class Certificate
    {
        public Certificate()
        {
        }

        public Certificate(byte[] rawCertificate)
        {
            var parsedCertificate = new X509Certificate2(rawCertificate);
            Thumbprint = parsedCertificate.Thumbprint;
            var name = parsedCertificate.FriendlyName;
            Name = string.IsNullOrEmpty(name) ? Thumbprint : name;
            var chain = new X509Chain();
            if (!chain.Build(parsedCertificate)) return;
            var temp = new List<string>();
            foreach (var cert in chain.ChainElements) temp.Add(cert.Certificate.Thumbprint);

            Chain = temp.ToArray();
        }

        public string Thumbprint { get; set; }
        public string Name { get; set; }
        public string[] Chain { get; set; } = Array.Empty<string>();
    }
}