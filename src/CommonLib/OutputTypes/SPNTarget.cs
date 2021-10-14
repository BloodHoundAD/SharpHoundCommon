namespace SharpHoundCommonLib.OutputTypes
{
    public class SPNTarget
    {
        public string ComputerSID { get; set; }
        public int Port { get; set; }
        public SPNService Service { get; set; }
    }

    public enum SPNService
    {
        MSSQL
    }
}