using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Security.Principal;
using System.Text;

namespace CommonLib
{
    internal static class Extensions
    {
        /// <summary>
        /// Helper function to print attributes of a SearchResultEntry
        /// </summary>
        /// <param name="searchResultEntry"></param>
        public static void PrintEntry(this SearchResultEntry searchResultEntry)
        {
            var sb = new StringBuilder();
            foreach (var propertyName in searchResultEntry.Attributes.AttributeNames)
            {
                var property = propertyName.ToString();
                sb.Append(property).Append("\t").Append(searchResultEntry.GetProperty(property)).Append("\n");
            }
            Logging.Log(sb.ToString());
        }


        #region SearchResultEntry
        /// <summary>
        /// Gets the specified property as a string from the SearchResultEntry
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
        /// Get's the string representation of the "objectguid" property from the SearchResultEntry
        /// </summary>
        /// <param name="entry"></param>
        /// <returns>The string representation of the object's GUID if possible, otherwise null</returns>
        public static string GetGuid(this SearchResultEntry entry)
        {
            if (entry.Attributes.Contains("objectguid"))
            {
                var guidBytes = entry.GetPropertyAsBytes("objectguid");

                return new Guid(guidBytes).ToString().ToUpper();
            }

            return null;
        }

        /// <summary>
        /// Gets the "objectsid" property as a string from the SearchResultEntry
        /// </summary>
        /// <param name="entry"></param>
        /// <returns>The string representation of the object's SID if possible, otherwise null</returns>
        public static string GetSid(this SearchResultEntry entry)
        {
            if (!entry.Attributes.Contains("objectsid")) return null;

            object[] s;
            try
            {
                s = entry.Attributes["objectsid"].GetValues(typeof(byte[]));
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
        /// Gets the specified property as a string array from the SearchResultEntry
        /// </summary>
        /// <param name="entry"></param>
        /// <param name="property">The LDAP name of the property you want to get</param>
        /// <returns>The specified property as an array of strings if possible, else an empty array</returns>
        public static string[] GetPropertyAsArray(this SearchResultEntry entry, string property)
        {
            if (!entry.Attributes.Contains(property))
                return new string[0];

            var values = entry.Attributes[property];
            var strings = values.GetValues(typeof(string));

            return strings is not string[] result ? null : result;
        }

        /// <summary>
        /// Gets the specified property as an array of byte arrays from the SearchResultEntry
        /// Used for SIDHistory
        /// </summary>
        /// <param name="entry"></param>
        /// <param name="property">The LDAP name of the property you want to get</param>
        /// <returns>The specified property as an array of bytes if possible, else an empty array</returns>
        public static byte[][] GetPropertyAsArrayOfBytes(this SearchResultEntry entry, string property)
        {
            var list = new List<byte[]>();
            if (!entry.Attributes.Contains(property))
                return list.ToArray();

            var values = entry.Attributes[property];
            var bytes = values.GetValues(typeof(byte[]));

            if (bytes is not byte[][] result)
                return null;

            return result;
        }

        /// <summary>
        /// Gets the specified property as a byte array
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
                return null;

            if (lookups[0] is not byte[] bytes || bytes.Length == 0)
                return null;

            return bytes;
        }

        /// <summary>
        /// Attempts to get the unique object identifier as used by BloodHound for the Search Result Entry. Tries to get objectsid first, and then objectguid next.
        /// </summary>
        /// <param name="entry"></param>
        /// <returns>String representation of the entry's object identifier or null</returns>
        public static string GetObjectIdentifier(this SearchResultEntry entry)
        {
            return entry.GetSid() ?? entry.GetGuid();
        }

        /// <summary>
        /// Extension method to determine the type of a SearchResultEntry.
        /// Requires objectsid, samaccounttype, objectclass
        /// </summary>
        /// <param name="searchResultEntry"></param>
        /// <returns></returns>
        public static LdapTypeEnum GetLdapType(this SearchResultEntry searchResultEntry)
        {
            var objectId = searchResultEntry.GetObjectIdentifier();
            if (objectId == null)
                return LdapTypeEnum.Unknown;

            if (searchResultEntry.GetPropertyAsBytes("msds-groupmsamembership") != null)
            {
                return LdapTypeEnum.User;
            }

            if (CommonPrincipal.GetCommonSid(objectId, out var commonPrincipal))
                return commonPrincipal.Type;

            var objectType = LdapTypeEnum.Unknown;
            var samAccountType = searchResultEntry.GetProperty("samaccounttype");
            //Its not a common principal. Lets use properties to figure out what it actually is
            if (samAccountType != null)
            {
                if (samAccountType == "805306370")
                    return LdapTypeEnum.Unknown;

                objectType = Helpers.SamAccountTypeToType(samAccountType);
            }
            else
            {
                var objectClasses = searchResultEntry.GetPropertyAsArray("objectClass");
                if (objectClasses == null)
                {
                    objectType = LdapTypeEnum.Unknown;
                }
                else if (objectClasses.Contains("groupPolicyContainer"))
                {
                    objectType = LdapTypeEnum.GPO;
                }
                else if (objectClasses.Contains("organizationalUnit"))
                {
                    objectType = LdapTypeEnum.OU;
                }
                else if (objectClasses.Contains("domain"))
                {
                    objectType = LdapTypeEnum.Domain;
                }
            }

            //Override GMSA object type
            if (searchResultEntry.GetPropertyAsBytes("msds-groupmsamembership") != null)
                objectType = LdapTypeEnum.User;

            return objectType;
        }

        #endregion
    }
}