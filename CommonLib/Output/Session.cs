namespace CommonLib.Output
{
    public class Session
    {
        private string _computer;
        private string _user;

        public string User
        {
            get => _user;
            set => _user = value?.ToUpper();
        }

        public string Computer
        {
            get => _computer;
            set => _computer = value?.ToUpper();
        }
    }
}