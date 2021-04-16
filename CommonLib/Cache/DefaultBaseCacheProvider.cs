namespace CommonLib
{
    public class DefaultBaseCacheProvider : BaseCacheProvider
    {
        public DefaultBaseCacheProvider(bool invalidateCache) : base(invalidateCache)
        {
        }

        internal override void GenerateCacheName()
        {
            throw new System.NotImplementedException();
        }
    }
}