using System;

namespace SharpHoundCommonLib.OutputTypes
{
    public class Domain : OutputBase
    {
        public ResultingGPOChanges GPOChanges = new();
        public TypedPrincipal[] ChildObjects { get; set; } = Array.Empty<TypedPrincipal>();
        public DomainTrust[] Trusts { get; set; } = Array.Empty<DomainTrust>();
        public GPLink[] Links { get; set; } = Array.Empty<GPLink>();
        public string[] InheritanceHashes { get; set; } = Array.Empty<string>();
        public string ForestRootIdentifier { get; set; }
    }
}