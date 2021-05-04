using CommonLib.Enums;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace CommonLib.Output
{
    public class ACE
    {
        public string PrincipalSID { get; set; }
        public Label PrincipalType { get; set; }
        public string RightName { get; set; }
        public string AceType { get; set; }
        public bool IsInherited { get; set; }

        public override string ToString()
        {
            return $"{PrincipalType} {PrincipalSID} - {RightName}/{AceType} {(IsInherited ? "" : "Not")} Inherited";
        }
    }

    [JsonConverter(typeof(StringEnumConverter))]
    public enum ACERightNames
    {
        GenericAll,
        WriteDacl,
        WriteOwner,
        GenericWrite,
        Owns,
        ReadLAPSPassword,
        ReadGMSAPassword,
    }

    [JsonConverter(typeof(StringEnumConverter))]
    public enum ACETypeNames
    {
        AllExtendedRights,
        ForceChangePassword,
        AddMember,
        AddAllowedToAct,
        GetChanges,
        GetChangesAll,
    }
}