using Newtonsoft.Json;

namespace CommonLib.OutputTypes
{
    public class LocalGroupAPIResult : APIResult
    {
        
        [JsonProperty(PropertyName = "members")]
        internal TypedPrincipal[] Results { get; set; } = new TypedPrincipal[0];
    }
}