using Newtonsoft.Json;

namespace CommonLib.Output
{
    public class APIResult
    {
        [JsonProperty(PropertyName = "collected")]
        internal bool Collected { get; set; } = false;
        [JsonProperty(PropertyName = "failure")]
        internal string FailureReason { get; set; } = null;
    }
}