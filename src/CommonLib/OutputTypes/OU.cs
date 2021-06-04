namespace SharpHoundCommonLib.OutputTypes
{
    public class OU : OutputBase
    {
        public GPLink[] Links { get; set; } = new GPLink[0];
        public TypedPrincipal[] ChildObjects { get; set; } = new TypedPrincipal[0];
    }
}