using SharpHoundCommonLib.Processors;

namespace SharpHoundCommonLib.OutputTypes
{
    public class CertAuthority : OutputBase
    {
        public TypedPrincipal[] Templates { get; set; }
        public string HostingComputer { get; set; }
        public bool IsUserSpecifiesSANEnabled { get; set; }
        public ACE[] CASecurity { get; set; }
        public EnrollmentAgentRestriction[] EnrollmentAgentRestrictions { get; set; }
    }
}