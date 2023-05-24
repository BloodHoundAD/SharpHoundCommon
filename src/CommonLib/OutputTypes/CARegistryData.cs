using SharpHoundCommonLib.Processors;

namespace SharpHoundCommonLib.OutputTypes
{
    public class CARegistryData
    {
        public CARegistryData()
        {
        }

        public CARegistryData(ACE[] cASecurity, EnrollmentAgentRestriction[] enrollmentAgentRestrictions, bool isUserSpecifiesSanEnabled)
        {
            this.CASecurity = cASecurity;
            this.EnrollmentAgentRestrictions = enrollmentAgentRestrictions;
            this.IsUserSpecifiesSanEnabled = isUserSpecifiesSanEnabled;
        }

        public ACE[] CASecurity { get; set; }
        public EnrollmentAgentRestriction[] EnrollmentAgentRestrictions { get; set; }
        public bool IsUserSpecifiesSanEnabled { get; set; }
    }
}