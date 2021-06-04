namespace SharpHoundCommonLib.OutputTypes
{
    public class SessionAPIResult : APIResult
    {
        public Session[] Results { get; set; } = new Session[0];
    }
}