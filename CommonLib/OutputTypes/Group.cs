namespace CommonLib.OutputTypes
{
    public class Group : OutputBase
    {
        public TypedPrincipal[] Members { get; set; } = new TypedPrincipal[0];
    }
}