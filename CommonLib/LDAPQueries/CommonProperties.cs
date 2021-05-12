namespace CommonLib.LDAPQuery
{
    public class CommonProperties
    {
        public static readonly string[] TypeResolutionProps = { "samaccounttype", "objectsid", "objectguid", "objectclass", "samaccountname", "msds-groupmsamembership" };
        public static readonly string[] ObjectID = { "objectsid", "objectguid" };
        public static readonly string[] ObjectSID = { "objectsid" };
        public static readonly string[] GPCFileSysPath = {"gpcfilesyspath"};
    }
}
