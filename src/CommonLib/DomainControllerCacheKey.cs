namespace SharpHoundCommonLib
{
    public class DomainControllerCacheKey
    {
        public string DomainName;
        public int Port;
        public bool GlobalCatalog;

        protected bool Equals(DomainControllerCacheKey other)
        {
            return DomainName == other.DomainName && Port == other.Port && GlobalCatalog == other.GlobalCatalog;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((DomainControllerCacheKey)obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = (DomainName != null ? DomainName.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ Port;
                hashCode = (hashCode * 397) ^ GlobalCatalog.GetHashCode();
                return hashCode;
            }
        }
    }
}