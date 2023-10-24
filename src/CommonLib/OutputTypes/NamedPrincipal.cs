namespace SharpHoundCommonLib.OutputTypes
{
    public class NamedPrincipal
    {
        public NamedPrincipal()
        {
        }

        public NamedPrincipal(string principalName, string objectId)
        {
            PrincipalName = principalName;
            ObjectId = objectId;
        }

        public string PrincipalName { get; set; }
        public string ObjectId { get; set; }

        public override string ToString()
        {
            return $"{PrincipalName} - {ObjectId}";
        }
    }
}