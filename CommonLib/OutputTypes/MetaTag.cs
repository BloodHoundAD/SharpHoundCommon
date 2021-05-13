using Newtonsoft.Json;

namespace SharpHoundCommonLib.OutputTypes
{
    public class MetaTag
    {
        [JsonProperty(PropertyName = "methods")]
        public long CollectionMethods { get; set; }
            
        [JsonProperty(PropertyName = "type")]
        public string DataType { get; set; }
        
        [JsonProperty(PropertyName = "count")]
        public long Count { get; set; }
    }
}