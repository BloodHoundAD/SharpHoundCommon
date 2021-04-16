namespace CommonLib
{
    public abstract class BaseCacheProvider
    {
        protected bool InvalidateCache;
        internal abstract void GenerateCacheName();

        protected BaseCacheProvider(bool invalidateCache, string filePath)
        {
            InvalidateCache = invalidateCache;
        }
    }
}