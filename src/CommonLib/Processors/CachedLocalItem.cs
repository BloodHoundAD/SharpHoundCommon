using SharpHoundCommonLib.Enums;

namespace SharpHoundCommonLib.Processors
{
    internal class CachedLocalItem
    {
        public CachedLocalItem(string name, Label type)
        {
            Name = name;
            Type = type;
        }

        public string Name { get; set; }
        public Label Type { get; set; }
    }
}