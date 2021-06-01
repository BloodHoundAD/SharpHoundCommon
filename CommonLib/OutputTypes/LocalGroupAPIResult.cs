namespace SharpHoundCommonLib.OutputTypes
{
    public class LocalGroupAPIResult : APIResult
    {
        public TypedPrincipal[] Results { get; set; } = new TypedPrincipal[0];
    }
}