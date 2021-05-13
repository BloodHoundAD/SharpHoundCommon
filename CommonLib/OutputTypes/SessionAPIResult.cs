using Newtonsoft.Json;

namespace SharpHoundCommonLib.OutputTypes
{
    public class SessionAPIResult : APIResult
    {
        [JsonProperty(PropertyName = "sessions")]
        internal Session[] Results { get; set; } = new Session[0];
    }
}