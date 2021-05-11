using Newtonsoft.Json;

namespace CommonLib.Output
{
    public class LocalGroupAPIResult : APIResult
    {
        
        [JsonProperty(PropertyName = "members")]
        internal TypedPrincipal[] Results { get; set; } = new TypedPrincipal[0];
    }
}