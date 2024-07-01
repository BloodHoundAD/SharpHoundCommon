using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Security.Cryptography.X509Certificates;
using SharpHoundCommonLib.Enums;

namespace SharpHoundCommonLib {
    public class SearchResultEntryWrapperNew : ISearchResultEntry {
        private readonly SearchResultEntry _entry;

        public string DistinguishedName => _entry.DistinguishedName;
        public ResolvedSearchResult ResolveBloodHoundInfo() {
        throw new System.NotImplementedException();
    }

        public string GetProperty(string propertyName) {
        throw new System.NotImplementedException();
    }

        public byte[] GetByteProperty(string propertyName) {
        throw new System.NotImplementedException();
    }

        public string[] GetArrayProperty(string propertyName) {
        throw new System.NotImplementedException();
    }

        public byte[][] GetByteArrayProperty(string propertyName) {
        throw new System.NotImplementedException();
    }

        public bool GetIntProperty(string propertyName, out int value) {
        throw new System.NotImplementedException();
    }

        public X509Certificate2[] GetCertificateArrayProperty(string propertyName) {
        throw new System.NotImplementedException();
    }

        public string GetObjectIdentifier() {
        throw new System.NotImplementedException();
    }

        public bool IsDeleted() {
        throw new System.NotImplementedException();
    }

        public Label GetLabel() {
        throw new System.NotImplementedException();
    }

        public string GetSid() {
        throw new System.NotImplementedException();
    }

        public string GetGuid() {
        throw new System.NotImplementedException();
    }

        public int PropCount(string prop) {
        throw new System.NotImplementedException();
    }

        public IEnumerable<string> PropertyNames() {
        throw new System.NotImplementedException();
    }

        public bool IsMSA() {
        throw new System.NotImplementedException();
    }

        public bool IsGMSA() {
        throw new System.NotImplementedException();
    }

        public bool HasLAPS() {
        throw new System.NotImplementedException();
    }
    }
}