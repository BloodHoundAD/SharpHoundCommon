using Microsoft.Win32;

namespace SharpHoundCommonLib
{
    public interface IRegistryKey
    {
        public void OpenSubKey(string subKey);
        public object GetValue(string name);
    }

    public class SHRegistryKey : IRegistryKey
    {
        private RegistryKey _currentKey;

        public SHRegistryKey(RegistryHive hive, string machineName)
        {
            var remoteKey = RegistryKey.OpenRemoteBaseKey(hive, machineName);
            _currentKey = remoteKey;
        }

        public void OpenSubKey(string subKey)
        {
            _currentKey = _currentKey.OpenSubKey(subKey);
        }

        public object GetValue(string name)
        {
            return _currentKey.GetValue(name);
        }
    }
}