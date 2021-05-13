using System.Collections.Generic;
using Newtonsoft.Json;

namespace SharpHoundCommonLib.OutputTypes
{
    public class OutputWrapper<T>
    {
        [JsonProperty(PropertyName = "meta")]
        internal MetaTag Meta { get; set; }
        [JsonProperty(PropertyName = "data")]
        internal List<T> Data { get; set; }
    }
}