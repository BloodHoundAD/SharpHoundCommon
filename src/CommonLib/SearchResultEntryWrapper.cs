using System;
using System.DirectoryServices.Protocols;
using SharpHoundCommonLib.Enums;

namespace SharpHoundCommonLib
{
    public interface ISearchResultEntry : IDisposable
    {
        string DistinguishedName
        {
            get;
        }
        
        string GetProperty(string propertyName);
        byte[] GetByteProperty(string propertyName);
        string[] GetArrayProperty(string propertyName);
        byte[][] GetByteArrayProperty(string propertyName);
        string GetObjectIdentifier();
        bool IsDeleted();
        Label GetLabel();
        string GetSid();
        string GetGuid();
    }
    
    public class SearchResultEntryWrapper : ISearchResultEntry
    {
        private readonly SearchResultEntry _entry;

        public SearchResultEntryWrapper(SearchResultEntry entry)
        {
            _entry = entry;
        }
        
        public string DistinguishedName => _entry.DistinguishedName;

        public void Dispose()
        {
        }
        
        public string GetProperty(string propertyName)
        {
            return _entry.GetProperty(propertyName);
        }

        public byte[] GetByteProperty(string propertyName)
        {
            return _entry.GetPropertyAsBytes(propertyName);
        }

        public string[] GetArrayProperty(string propertyName)
        {
            return _entry.GetPropertyAsArray(propertyName);
        }

        public byte[][] GetByteArrayProperty(string propertyName)
        {
            return _entry.GetPropertyAsArrayOfBytes(propertyName);
        }

        public string GetObjectIdentifier()
        {
            return _entry.GetObjectIdentifier();
        }

        public bool IsDeleted()
        {
            return _entry.IsDeleted();
        }

        public Label GetLabel()
        {
            return _entry.GetLabel();
        }

        public string GetSid()
        {
            return _entry.GetSid();
        }

        public string GetGuid()
        {
            return _entry.GetGuid();
        }

        public SearchResultEntry GetEntry()
        {
            return _entry;
        }
    }
}