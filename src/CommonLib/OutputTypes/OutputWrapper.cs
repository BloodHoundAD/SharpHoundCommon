using System.Collections.Generic;

namespace SharpHoundCommonLib.OutputTypes
{
    public class OutputWrapper<T>
    {
        internal MetaTag Meta { get; set; }
        internal List<T> Data { get; set; }
    }
}