namespace SharpHoundCommonLib.OutputTypes
{
    public class User : OutputBase
    {
        public TypedPrincipal[] AllowedToDelegate { get; set; } = new TypedPrincipal[0];
        public string PrimaryGroupSID { get; set; }
        public TypedPrincipal[] HasSIDHistory { get; set; } = new TypedPrincipal[0];
        public SPNTarget[] SpnTargets { get; set; } = new SPNTarget[0];
    }
}