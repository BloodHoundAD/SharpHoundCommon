using Newtonsoft.Json;

namespace CommonLib.Output
{
    /// <summary>
    /// Represents a computer object in Active Directory. Contains all the properties BloodHound cares about 
    /// </summary>
    public class Computer : OutputBase
    {
        public string PrimaryGroupSID { get; set; }
        public TypedPrincipal[] AllowedToDelegate { get; set; } = new TypedPrincipal[0];
        public TypedPrincipal[] AllowedToAct { get; set; } = new TypedPrincipal[0];
        public Session[] Sessions { get; set; } = new Session[0];
        public LocalGroupResult Admins { get; set; } = new();
        public LocalGroupResult RemoteDesktopUsers { get; set; } = new();
        public LocalGroupResult DcomUsers { get; set; } = new();
        public LocalGroupResult PSRemoteUsers { get; set; } = new();
        public ComputerStatus Status { get; set; }
    }

    public class ComputerStatus
    {
        public bool Connectable { get; set; }
        public string Error { get; set; }
    }
    
    public class LocalGroupResult
    {
        internal bool Collected { get; set; } = false;
        [JsonProperty(PropertyName = "failure")]
        internal string FailureReason { get; set; } = null;
        internal string[] Members { get; set; } = new string[0];
    }
}