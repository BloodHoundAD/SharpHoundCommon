using SharpHoundCommonLib.Enums;

namespace SharpHoundCommonLib.OutputTypes
{
    public class ACE
    {
        public string PrincipalSID { get; set; }
        public Label PrincipalType { get; set; }
        public string RightName { get; set; }
        public bool IsInherited { get; set; }

        public override string ToString()
        {
            return $"{PrincipalType} {PrincipalSID} - {RightName} {(IsInherited ? "" : "Not")} Inherited";
        }
    }
}