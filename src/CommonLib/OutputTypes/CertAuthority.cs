namespace SharpHoundCommonLib.OutputTypes
{
    public class CertAuthority : OutputBase
    {
        public TypedPrincipal[] Templates { get; set; }
        public string HostingComputer { get; set; }
        public ACE[] CASecurity { get; set; }
        public Certificate Certificate { get; set; }
        public bool IsEnterpriseCA { get; set; }
        public bool IsRootCA { get; set; }
        public CARegistryData CARegistryData { get; set; }
    }
}