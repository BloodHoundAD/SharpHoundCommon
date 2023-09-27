using SharpHoundCommonLib.Processors;

namespace SharpHoundCommonLib.OutputTypes
{
    public class CARegistryData
    {
        public ACE[] CASecurity { get; set; }
        public EnrollmentAgentRestriction[] EnrollmentAgentRestrictions { get; set; }
        public bool IsUserSpecifiesSanEnabled { get; set; }
        public bool CASecurityCollected { get; set; }
        public bool EnrollmentAgentRestrictionsCollected { get; set; }
        public bool IsUserSpecifiesSanEnabledCollected { get; set; }

        public CARegistryData(ACE[] cASecurity,
                              EnrollmentAgentRestriction[] enrollmentAgentRestrictions,
                              bool isUserSpecifiesSanEnabled,
                              bool cASecurityCollected,
                              bool enrollmentAgentRestrictionsCollected,
                              bool isUserSpecifiesSanEnabledCollected)
        {
            CASecurity = cASecurity;
            EnrollmentAgentRestrictions = enrollmentAgentRestrictions;
            IsUserSpecifiesSanEnabled = isUserSpecifiesSanEnabled;
            CASecurityCollected = cASecurityCollected;
            EnrollmentAgentRestrictionsCollected = enrollmentAgentRestrictionsCollected;
            IsUserSpecifiesSanEnabledCollected = isUserSpecifiesSanEnabledCollected;
        }

    }
}