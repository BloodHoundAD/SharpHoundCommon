using System.Collections.Generic;

namespace SharpHoundCommonLib.OutputTypes
{
    /// <summary>
    /// Represents a base JSON object which other objects will inherit from.
    /// </summary>
    public class OutputBase
    {
        public ACE[] Aces { get; set; } = new ACE[0];
        public string ObjectIdentifier { get; set; }
        public Dictionary<string, object> Properties = new Dictionary<string, object>();
        public bool IsDeleted { get; set; }
    }
}