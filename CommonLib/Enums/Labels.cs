using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace SharpHoundCommonLib.Enums
{
    [JsonConverter(typeof(StringEnumConverter))]
    public enum Label
    {
        User,
        Computer,
        Group,
        GPO,
        Domain,
        OU,
        Container,
        Base
    }
}