using System;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using SharpHoundCommonLib.Enums;

namespace SharpHoundCommonLib;

public static class SearchResultEntryExtensions {
    /// <summary>
    ///     Extension method to determine the BloodHound type of a SearchResultEntry using LDAP properties
    ///     Requires ldap properties objectsid, samaccounttype, objectclass
    /// </summary>
    /// <param name="entry"></param>
    /// <returns></returns>
    public static bool GetLabel(this SearchResultEntry entry, out Label type)
    {
        if (!entry.GetPropertyAsInt(LDAPProperties.Flags, out var flags)) {
            flags = 0;
        }

        return LdapUtils.ResolveLabel(entry.GetObjectIdentifier(), entry.DistinguishedName,
            entry.GetProperty(LDAPProperties.SAMAccountType), entry.GetPropertyAsArray(LDAPProperties.ObjectClass),
            flags, out type);
    }
    
    /// <summary>
        ///     Gets the specified property as a string from the SearchResultEntry
        /// </summary>
        /// <param name="entry"></param>
        /// <param name="property">The LDAP name of the property you want to get</param>
        /// <returns>The string value of the property if it exists or null</returns>
        public static string GetProperty(this SearchResultEntry entry, string property)
        {
            if (!entry.Attributes.Contains(property))
                return null;

            var collection = entry.Attributes[property];
            //Use GetValues to auto-convert to the proper type
            var lookups = collection.GetValues(typeof(string));
            if (lookups.Length == 0)
                return null;

            if (lookups[0] is not string prop || prop.Length == 0)
                return null;

            return prop;
        }

        /// <summary>
        ///     Get's the string representation of the "objectguid" property from the SearchResultEntry
        /// </summary>
        /// <param name="entry"></param>
        /// <returns>The string representation of the object's GUID if possible, otherwise null</returns>
        public static string GetGuid(this SearchResultEntry entry)
        {
            if (entry.Attributes.Contains(LDAPProperties.ObjectGUID))
            {
                var guidBytes = entry.GetPropertyAsBytes(LDAPProperties.ObjectGUID);

                return new Guid(guidBytes).ToString().ToUpper();
            }

            return null;
        }

        /// <summary>
        ///     Gets the "objectsid" property as a string from the SearchResultEntry
        /// </summary>
        /// <param name="entry"></param>
        /// <returns>The string representation of the object's SID if possible, otherwise null</returns>
        public static string GetSid(this SearchResultEntry entry)
        {
            if (!entry.Attributes.Contains(LDAPProperties.ObjectSID)) return null;

            object[] s;
            try
            {
                s = entry.Attributes[LDAPProperties.ObjectSID].GetValues(typeof(byte[]));
            }
            catch (NotSupportedException)
            {
                return null;
            }

            if (s.Length == 0)
                return null;

            if (s[0] is not byte[] sidBytes || sidBytes.Length == 0)
                return null;

            try
            {
                var sid = new SecurityIdentifier(sidBytes, 0);
                return sid.Value.ToUpper();
            }
            catch (ArgumentNullException)
            {
                return null;
            }
        }

        /// <summary>
        ///     Gets the specified property as a string array from the SearchResultEntry
        /// </summary>
        /// <param name="entry"></param>
        /// <param name="property">The LDAP name of the property you want to get</param>
        /// <returns>The specified property as an array of strings if possible, else an empty array</returns>
        public static string[] GetPropertyAsArray(this SearchResultEntry entry, string property)
        {
            if (!entry.Attributes.Contains(property))
                return Array.Empty<string>();

            var values = entry.Attributes[property];
            var strings = values.GetValues(typeof(string));

            return strings is not string[] result ? Array.Empty<string>() : result;
        }

        /// <summary>
        ///     Gets the specified property as an array of byte arrays from the SearchResultEntry
        ///     Used for SIDHistory
        /// </summary>
        /// <param name="entry"></param>
        /// <param name="property">The LDAP name of the property you want to get</param>
        /// <returns>The specified property as an array of bytes if possible, else an empty array</returns>
        public static byte[][] GetPropertyAsArrayOfBytes(this SearchResultEntry entry, string property)
        {
            if (!entry.Attributes.Contains(property))
                return Array.Empty<byte[]>();

            var values = entry.Attributes[property];
            var bytes = values.GetValues(typeof(byte[]));

            return bytes is not byte[][] result ? Array.Empty<byte[]>() : result;
        }

        /// <summary>
        ///     Gets the specified property as a byte array
        /// </summary>
        /// <param name="searchResultEntry"></param>
        /// <param name="property">The LDAP name of the property you want to get</param>
        /// <returns>An array of bytes if possible, else null</returns>
        public static byte[] GetPropertyAsBytes(this SearchResultEntry searchResultEntry, string property)
        {
            if (!searchResultEntry.Attributes.Contains(property))
                return null;

            var collection = searchResultEntry.Attributes[property];
            var lookups = collection.GetValues(typeof(byte[]));

            if (lookups.Length == 0)
                return Array.Empty<byte>();

            if (lookups[0] is not byte[] bytes || bytes.Length == 0)
                return Array.Empty<byte>();

            return bytes;
        }

        /// <summary>
        ///     Gets the specified property as an int
        /// </summary>
        /// <param name="entry"></param>
        /// <param name="property"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public static bool GetPropertyAsInt(this SearchResultEntry entry, string property, out int value)
        {
            var prop = entry.GetProperty(property);
            if (prop != null) return int.TryParse(prop, out value);
            value = 0;
            return false;
        }

        /// <summary>
        ///     Gets the specified property as an array of X509 certificates.
        /// </summary>
        /// <param name="searchResultEntry"></param>
        /// <param name="property"></param>
        /// <returns></returns>
        public static X509Certificate2[] GetPropertyAsArrayOfCertificates(this SearchResultEntry searchResultEntry,
            string property)
        {
            if (!searchResultEntry.Attributes.Contains(property))
                return null;

            return searchResultEntry.GetPropertyAsArrayOfBytes(property).Select(x => new X509Certificate2(x)).ToArray();
        }


        /// <summary>
        ///     Attempts to get the unique object identifier as used by BloodHound for the Search Result Entry. Tries to get
        ///     objectsid first, and then objectguid next.
        /// </summary>
        /// <param name="entry"></param>
        /// <returns>String representation of the entry's object identifier or null</returns>
        public static string GetObjectIdentifier(this SearchResultEntry entry)
        {
            return entry.GetSid() ?? entry.GetGuid();
        }

        /// <summary>
        ///     Checks the isDeleted LDAP property to determine if an entry has been deleted from the directory
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public static bool IsDeleted(this SearchResultEntry entry)
        {
            var deleted = entry.GetProperty(LDAPProperties.IsDeleted);
            return bool.TryParse(deleted, out var isDeleted) && isDeleted;
        }
        
        /// <summary>
        ///     Helper function to print attributes of a SearchResultEntry
        /// </summary>
        /// <param name="searchResultEntry"></param>
        public static string PrintEntry(this SearchResultEntry searchResultEntry)
        {
            var sb = new StringBuilder();
            if (searchResultEntry.Attributes.AttributeNames == null) return sb.ToString();
            foreach (var propertyName in searchResultEntry.Attributes.AttributeNames)
            {
                var property = propertyName.ToString();
                sb.Append(property).Append("\t").Append(searchResultEntry.GetProperty(property)).Append("\n");
            }

            return sb.ToString();
        }
}