using System;

namespace SharpHoundCommonLib.OutputTypes
{
    public class Container : OutputBase
    {
        public TypedPrincipal[] ChildObjects { get; set; } = Array.Empty<TypedPrincipal>();
        public string[] InheritanceHashes { get; set; } = Array.Empty<string>();
    }
}