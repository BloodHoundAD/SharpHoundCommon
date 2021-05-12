namespace CommonLib.LDAPQueries
{
    public class CommonFilters
    {
        public static string EnabledOnly => "(!(UserAccountControl:1.2.840.113556.1.4.803:=2))";
        
        public static string NeedsGPCFilePath => "(gpcfilesyspath=*)";
        
        public static string SpecificSID(string sid)
        {
            var hSid = Helpers.ConvertSidToHexSid(sid);
            return $"(objectsid={hSid})";
        }

        public static string NeedsSPN => "(serviceprincipalname=*)";
    }
}