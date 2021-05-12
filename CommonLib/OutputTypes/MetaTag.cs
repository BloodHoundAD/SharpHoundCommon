using Newtonsoft.Json;

namespace CommonLib.Output
{
    public class MetaTag
    {
        [JsonProperty(PropertyName = "methods")]
        internal long CollectionMethods { get; set; }
            
        [JsonProperty(PropertyName = "type")]
        internal string DataType { get; set; }
        
        [JsonProperty(PropertyName = "count")]
        internal long Count { get; set; }
    }
}