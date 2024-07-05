using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.Principal;
using System.Text;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.LDAPQueries;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib;

public static class DirectoryEntryExtensions {
    public static string GetProperty(this DirectoryEntry entry, string propertyName) {
            try {
                if (!entry.Properties.Contains(propertyName))
                    entry.RefreshCache(new[] { propertyName });
                
                if (!entry.Properties.Contains(propertyName))
                    return null;
            }
            catch {
                return null;
            }

            var s = entry.Properties[propertyName][0];
            return s switch
            {
                string st => st,
                _ => null
            };
        }

        public static string[] GetPropertyAsArray(this DirectoryEntry entry, string propertyName) {
            try {
                if (!entry.Properties.Contains(propertyName))
                    entry.RefreshCache(new[] { propertyName });
                
                if (!entry.Properties.Contains(propertyName))
                    return null;
            }
            catch {
                return null;
            }

            var dest = new List<string>();
            foreach (var val in entry.Properties[propertyName]) {
                if (val is string s) {
                    dest.Add(s);
                }
            }

            return dest.ToArray();
        }

        public static bool GetTypedPrincipal(this DirectoryEntry entry, out TypedPrincipal principal) {
            var identifier = entry.GetObjectIdentifier();
            var success = entry.GetLabel(out var label);
            principal = new TypedPrincipal(identifier, label);
            return (success && !string.IsNullOrWhiteSpace(identifier));
        }

        public static string GetObjectIdentifier(this DirectoryEntry entry) {
            return entry.GetSid() ?? entry.GetGuid();
        }

        public static string GetSid(this DirectoryEntry entry)
        {
            try
            {
                if (!entry.Properties.Contains(LDAPProperties.ObjectSID))
                    entry.RefreshCache(new[] { LDAPProperties.ObjectSID });

                if (!entry.Properties.Contains(LDAPProperties.ObjectSID))
                    return null;
            }
            catch
            {
                return null;
            }

            var s = entry.Properties[LDAPProperties.ObjectSID][0];
            return s switch
            {
                byte[] b => new SecurityIdentifier(b, 0).ToString(),
                string st => new SecurityIdentifier(Encoding.ASCII.GetBytes(st), 0).ToString(),
                _ => null
            };
        }
        
        public static string GetGuid(this DirectoryEntry entry)
        {
            try
            {
                //Attempt to refresh the props first
                if (!entry.Properties.Contains(LDAPProperties.ObjectGUID))
                    entry.RefreshCache(new[] { LDAPProperties.ObjectGUID });

                if (!entry.Properties.Contains(LDAPProperties.ObjectGUID))
                    return null;
            }
            catch
            {
                return null;
            }

            var s = entry.Properties[LDAPProperties.ObjectGUID][0];
            return s switch
            {
                byte[] b => new Guid(b).ToString(),
                string st => st,
                _ => null
            };
        }
        
        
        public static bool GetLabel(this DirectoryEntry entry, out Label type) {
            try {
                entry.RefreshCache(CommonProperties.TypeResolutionProps);
            }
            catch {
                //pass
            }

            var flagString = entry.GetProperty(LDAPProperties.Flags);
            if (!int.TryParse(flagString, out var flags)) {
                flags = 0;
            }

            return LdapUtils.ResolveLabel(entry.GetObjectIdentifier(), entry.GetProperty(LDAPProperties.DistinguishedName),
                entry.GetProperty(LDAPProperties.SAMAccountType),
                entry.GetPropertyAsArray(LDAPProperties.SAMAccountType), flags, out type);
        }
}