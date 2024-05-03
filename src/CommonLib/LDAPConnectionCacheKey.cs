namespace SharpHoundCommonLib
{
    public class LDAPConnectionCacheKey
    {
        public int Port;
        public bool GlobalCatalog;
        public string Domain;

        protected bool Equals(LDAPConnectionCacheKey other)
        {
            return Port == other.Port && GlobalCatalog == other.GlobalCatalog && Domain == other.Domain;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((LDAPConnectionCacheKey)obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = Port;
                hashCode = (hashCode * 397) ^ GlobalCatalog.GetHashCode();
                hashCode = (hashCode * 397) ^ (Domain != null ? Domain.GetHashCode() : 0);
                return hashCode;
            }
        }
    }
}