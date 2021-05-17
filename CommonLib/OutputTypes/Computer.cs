namespace SharpHoundCommonLib.OutputTypes
{
    /// <summary>
    /// Represents a computer object in Active Directory. Contains all the properties BloodHound cares about 
    /// </summary>
    public class Computer : OutputBase
    {
        public string PrimaryGroupSID { get; set; }
        public TypedPrincipal[] AllowedToDelegate { get; set; } = new TypedPrincipal[0];
        public TypedPrincipal[] AllowedToAct { get; set; } = new TypedPrincipal[0];
        public TypedPrincipal[] HasSIDHistory { get; set; } = new TypedPrincipal[0];
        public SessionAPIResult Sessions { get; set; } = new();
        public LocalGroupAPIResult Admins { get; set; } = new();
        public LocalGroupAPIResult RemoteDesktopUsers { get; set; } = new();
        public LocalGroupAPIResult DcomUsers { get; set; } = new();
        public LocalGroupAPIResult PSRemoteUsers { get; set; } = new();
        public ComputerStatus Status { get; set; }
    }

    public class ComputerStatus
    {
        public bool Connectable { get; set; }
        public string Error { get; set; }
    }
}