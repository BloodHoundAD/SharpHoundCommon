using Newtonsoft.Json;

namespace CommonLib.OutputTypes
{
    public class APIResult
    {
        [JsonProperty(PropertyName = "collected")]
        internal bool Collected { get; set; }
        [JsonProperty(PropertyName = "failure")]
        internal string FailureReason { get; set; }
    }
}