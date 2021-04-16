namespace CommonLib
{
    public interface ISharpHoundCache
    {
        internal void LoadCache();
        internal void SaveCache();
        internal void GenerateCacheName();
        
    }
}