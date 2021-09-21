using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.Processors;

namespace SharpHoundCommonLib.OutputTypes
{
    public class CertAuthority : OutputBase
    {
        public PKICertificateAuthorityFlags Flags { get; set; }
        public TypedPrincipal[] Templates { get; set; }
        public string HostingComputer { get; set; }
        public bool IsUserSpecifiesSANEnabled { get; set; }
        public ACE[] CASecurity { get; set; }
        public EnrollmentAgentRestriction[] EnrollmentAgentRestrictions { get; set; }
    }
}