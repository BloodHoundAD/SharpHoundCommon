namespace CommonLib.Output
{
    public class DomainTrust
    {
        public string TargetDomainSid { get; set; }
        public string TargetDomainName { get; set; }
        public bool IsTransitive { get; set; }
        public bool SidFilteringEnabled { get; set; }
        public TrustDirection TrustDirection { get; set; }
        public TrustType TrustType { get; set; }
    }
    
    public enum TrustDirection
    {
        Disabled = 0,
        Inbound = 1,
        Outbound = 2,
        Bidirectional = 3
    }

    public enum TrustType
    {
        ParentChild,
        CrossLink,
        Forest,
        External,
        Unknown
    }
}