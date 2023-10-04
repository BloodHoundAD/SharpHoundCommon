﻿namespace SharpHoundCommonLib.OutputTypes
{
    public class EnterpriseCA : OutputBase
    {
        public TypedPrincipal[] EnabledCertTemplates { get; set; }
        public string HostingComputer { get; set; }
        public string CertThumbprint { get; set; }
        public Certificate Certificate { get; set; }
        public CARegistryData CARegistryData { get; set; }
    }
}