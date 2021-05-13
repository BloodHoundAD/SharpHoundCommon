namespace SharpHoundCommonLib.OutputTypes
{
    public class Container : OutputBase
    {
        public TypedPrincipal[] ChildObjects { get; set; } = new TypedPrincipal[0];
    }
}