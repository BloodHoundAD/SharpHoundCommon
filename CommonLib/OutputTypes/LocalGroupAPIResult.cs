using Newtonsoft.Json;

namespace SharpHoundCommonLib.OutputTypes
{
    public class LocalGroupAPIResult : APIResult
    {
        [JsonProperty(PropertyName = "members")]
        internal TypedPrincipal[] Results { get; set; } = new TypedPrincipal[0];
    }
}