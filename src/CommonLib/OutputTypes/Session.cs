namespace SharpHoundCommonLib.OutputTypes
{
    public class Session
    {
        private string _computerSID;
        private string _userSID;

        public string UserSID
        {
            get => _userSID;
            set => _userSID = value?.ToUpper();
        }

        public string ComputerSID
        {
            get => _computerSID;
            set => _computerSID = value?.ToUpper();
        }
    }
}