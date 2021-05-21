using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace CommonLib.Output
{
    public class SPNTarget
    {
        public string ComputerSID { get; set; }
        public int Port { get; set; }
        public SPNService Service { get; set; }
    }

    [JsonConverter(typeof(StringEnumConverter))]
    public enum SPNService
    {
        MSSQl
    }
}