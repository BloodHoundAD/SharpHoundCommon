namespace SharpHoundCommonLib.OutputTypes
{
    public class Domain : OutputBase
    {
        public TypedPrincipal[] ChildObjects { get; set; } = new TypedPrincipal[0];
        public DomainTrust[] Trusts { get; set; } = new DomainTrust[0];
        public GPLink[] GPLinks { get; set; } = new GPLink[0];
    }
}