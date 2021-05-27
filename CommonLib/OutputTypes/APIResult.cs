using Newtonsoft.Json;

namespace SharpHoundCommonLib.OutputTypes
{
    public class APIResult
    {
        [JsonProperty(PropertyName = "collected")]
        public bool Collected { get; set; }
        [JsonProperty(PropertyName = "failure")]
        public string FailureReason { get; set; }
    }
}