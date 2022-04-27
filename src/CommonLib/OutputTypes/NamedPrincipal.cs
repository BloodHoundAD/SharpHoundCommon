namespace SharpHoundCommonLib.OutputTypes
{
    public class NamedPrincipal
    {
        public string PrincipalName { get; set; }
        public string ObjectId { get; set; }
        public NamedPrincipal(){}

        public NamedPrincipal(string principalName, string objectId)
        {
            PrincipalName = principalName;
            ObjectId = objectId;
        }

        public override string ToString()
        {
            return $"{PrincipalName} - {ObjectId}";
        }
    }
}