namespace CommonLib.LDAPQuery
{
    public class CommonProperties
    {
        public static readonly string[] ResolutionProps = { "samaccounttype", "objectsid", "objectguid", "objectclass", "samaccountname", "msds-groupmsamembership" };
        public static readonly string[] ObjectID = { "objectsid", "objectguid" };
    }
}