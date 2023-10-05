namespace SharpHoundCommonLib.OutputTypes
{
    public class EnterpriseCA : OutputBase
    {
        public TypedPrincipal[] EnabledCertTemplates { get; set; }
        public string HostingComputer { get; set; }
        public CARegistryData CARegistryData { get; set; }
    }
}