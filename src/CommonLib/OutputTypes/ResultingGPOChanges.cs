using System;
using System.Collections.Generic;

namespace SharpHoundCommonLib.OutputTypes
{
    public class ResultingGPOChanges
    {
        public Dictionary<string, int> PasswordPolicies = new();
        public Dictionary<string, bool> SMBSigning = new();
        public Dictionary<string, bool> LDAPSigning = new();
        public Dictionary<string, object> LMAuthenticationLevel = new();
        public TypedPrincipal[] LocalAdmins { get; set; } = Array.Empty<TypedPrincipal>();
        public TypedPrincipal[] RemoteDesktopUsers { get; set; } = Array.Empty<TypedPrincipal>();
        public TypedPrincipal[] DcomUsers { get; set; } = Array.Empty<TypedPrincipal>();
        public TypedPrincipal[] PSRemoteUsers { get; set; } = Array.Empty<TypedPrincipal>();
        public TypedPrincipal[] AffectedComputers { get; set; } = Array.Empty<TypedPrincipal>();
    }
}