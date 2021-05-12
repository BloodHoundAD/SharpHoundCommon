using Newtonsoft.Json;

namespace CommonLib.OutputTypes
{
    public class SessionAPIResult : APIResult
    {
        [JsonProperty(PropertyName = "sessions")]
        internal Session[] Results { get; set; } = new Session[0];
    }
}