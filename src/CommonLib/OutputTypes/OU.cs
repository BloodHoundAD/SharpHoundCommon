using System;

namespace SharpHoundCommonLib.OutputTypes
{
    public class OU : OutputBase
    {
        public ResultingGPOChanges GPOChanges = new();
        public GPLink[] Links { get; set; } = Array.Empty<GPLink>();
        public TypedPrincipal[] ChildObjects { get; set; } = Array.Empty<TypedPrincipal>();
        public string[] InheritanceHashes { get; set; } = Array.Empty<string>();
    }
}