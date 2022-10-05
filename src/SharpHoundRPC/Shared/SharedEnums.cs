namespace SharpHoundRPC.Shared
{
    public class SharedEnums
    {
        public enum SidNameUse
        {
            User = 1,
            Group,
            Domain,
            Alias,
            WellKnownGroup,
            DeletedAccount,
            Invalid,
            Unknown,
            Computer,
            Label,
            LogonSession
        }
    }
}