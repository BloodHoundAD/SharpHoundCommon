namespace CommonLib.Output
{
    public class GPLink
    {
        private string _guid;
        
        public bool IsEnforced { get; set; }
        public string GUID { get => _guid; set => _guid = value?.ToUpper(); }
    }
}