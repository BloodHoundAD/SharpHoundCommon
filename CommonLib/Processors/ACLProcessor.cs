using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Security.AccessControl;
using System.Security.Principal;
using CommonLib.Enums;
using CommonLib.Output;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;

namespace CommonLib.Processors
{
    public static class ACLProcessor
    {
        private static readonly Dictionary<Type, string> BaseGuids;
        private const string AllGuid = "00000000-0000-0000-0000-000000000000";
        private static ConcurrentDictionary<string, string> _guidMap = new();

        static ACLProcessor()
        {
            //Create a dictionary with the base GUIDs of each object type
            BaseGuids = new Dictionary<Type, string>
            {
                {typeof(User), "bf967aba-0de6-11d0-a285-00aa003049e2"},
                {typeof(Computer), "bf967a86-0de6-11d0-a285-00aa003049e2"},
                {typeof(Group), "bf967a9c-0de6-11d0-a285-00aa003049e2"},
                {typeof(Domain), "19195a5a-6da0-11d0-afd3-00c04fd930c9"},
                {typeof(GPO), "f30e3bc2-9ff0-11d1-b603-0000f80367c1"},
                {typeof(OU), "bf967aa5-0de6-11d0-a285-00aa003049e2"}
            };
        }

        internal static void BuildGUIDCache()
        {
            var instance = LDAPUtils.Instance; 
            var forest = instance.GetForest();
            if (forest == null)
                return;

            var schema = forest.Schema.Name;
            foreach (var entry in instance.QueryLDAP("(schemaIDGUID=*)", SearchScope.Subtree,
                new[] {"schemaidguid", "name"}, adsPath: schema))
            {
                var name = entry.GetProperty("name")?.ToLower();
                var guid = new Guid(entry.GetPropertyAsBytes("schemaidguid")).ToString();
                _guidMap.TryAdd(guid, name);
            }
        }

        public static IEnumerable<ACE> ProcessNTSecurityDescriptor(SearchResultEntry entry, string objectDomain, Label objectType)
        {
            var ntSecurityDescriptor = entry.GetPropertyAsBytes("ntsecuritydescriptor");
            var descriptor = new ActiveDirectorySecurity();
            descriptor.SetSecurityDescriptorBinaryForm(ntSecurityDescriptor);
            var instance = LDAPUtils.Instance;

            var ownerSid = PreProcessSID(descriptor.GetOwner(typeof(SecurityIdentifier)).Value);

            if (ownerSid != null)
            {
                var resolvedOwner = instance.ResolveSidAndType(ownerSid, objectDomain);
                if (resolvedOwner != null)
                    yield return new ACE
                    {
                        PrincipalType = resolvedOwner.ObjectType,
                        PrincipalSID = resolvedOwner.ObjectIdentifier,
                        AceType = "",
                        RightName = "Owner",
                        IsInherited = false
                    };
            }

            foreach (ActiveDirectoryAccessRule ace in descriptor.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (ace == null)
                    continue;
                
                if (ace.AccessControlType == AccessControlType.Deny)
                    continue;

                if (!IsAceInherited(ace, BaseGuids[objectType.GetType()]))
                    continue;

                var principalSid = PreProcessSID(ace.IdentityReference.Value);
                
                if (principalSid == null)
                    continue;

                var resolvedPrincipal = instance.ResolveSidAndType(principalSid, objectDomain);

                var aceRights = ace.ActiveDirectoryRights;
                var aceType = ace.ObjectType.ToString();
                var inherited = ace.IsInherited;

                _guidMap.TryGetValue(aceType, out var mappedGuid);

                var bAce = new ACE
                {
                    PrincipalType = resolvedPrincipal.ObjectType,
                    PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                    IsInherited = inherited,
                };

                //GenericAll applies to every object
                if (aceRights.HasFlag(ActiveDirectoryRights.GenericAll))
                {
                    if (aceType is AllGuid or "")
                    {
                        bAce.AceType = "";
                        bAce.RightName = "GenericAll";
                        yield return bAce;
                    }
                    //This is a special case. If we don't continue here, every other ACE will match because GenericAll includes all other permissions
                    continue;
                }

                //WriteDACL and WriteOwner are always useful no matter what the object type is as well because they enable all other attacks
                if (aceRights.HasFlag(ActiveDirectoryRights.WriteDacl))
                {
                    bAce.RightName = "WriteDacl";
                    bAce.AceType = "";
                    yield return bAce;
                }
                
                if (aceRights.HasFlag(ActiveDirectoryRights.WriteOwner))
                {
                    bAce.RightName = "WriteOwner";
                    bAce.AceType = "";
                    yield return bAce;
                }
                
                //Process object type specific ACEs. Extended rights apply to users, domains, and computers
                if (aceRights.HasFlag(ActiveDirectoryRights.ExtendedRight))
                {
                    if (objectType == Label.Domain)
                    {
                        if (aceType == "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")
                        {
                            bAce.RightName = "ExtendedRight";
                            bAce.AceType = "GetChanges";
                            yield return bAce;
                        }else if (aceType == "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"){
                            bAce.RightName = "ExtendedRight";
                            bAce.AceType = "GetChangesAll";
                            yield return bAce;
                        }else if (aceType is AllGuid or "")
                        {
                            bAce.RightName = "ExtendedRight";
                            bAce.AceType = "All";
                            yield return bAce;
                        }
                    }else if (objectType == Label.User){
                        if (aceType == "00299570-246d-11d0-a768-00aa006e0529"){
                            bAce.RightName = "ForceChangePassword";
                            bAce.AceType = "GetChangesAll";
                            yield return bAce;
                        }else if (aceType is AllGuid or ""){
                            bAce.RightName = "ExtendedRight";
                            bAce.AceType = "All";
                            yield return bAce;
                        }
                    }else if (objectType == Label.Computer){
                        //ReadLAPSPassword is only applicable if the computer actually has LAPS. Check the world readable property ms-mcs-admpwdexpirationtime
                        if (entry.GetProperty("ms-mcs-admpwdexpirationtime") != null)
                        {
                            if (aceType is AllGuid or ""){
                                bAce.RightName = "ExtendedRight";
                                bAce.AceType = "All";
                                yield return bAce;
                            }else if (mappedGuid is "ms-mcs-admpwd")
                            {
                                bAce.RightName = "ReadLAPSPassword";
                                bAce.AceType = "";
                                yield return bAce;
                            }
                        }
                    }
                }

                //GenericWrite encapsulates WriteProperty, so process them in tandem to avoid duplicate edges
                if (aceRights.HasFlag(ActiveDirectoryRights.GenericWrite) ||
                    aceRights.HasFlag(ActiveDirectoryRights.WriteProperty))
                {
                    if (objectType is Label.User or Label.Group or Label.Computer or Label.GPO)
                    {
                        if (aceType is AllGuid or "")
                        {
                            bAce.RightName = "GenericWrite";
                            bAce.AceType = "";
                            yield return bAce;
                        }
                    }

                    if (objectType == Label.User && aceType == "f3a64788-5306-11d1-a9c5-0000f80367c1")
                    {
                        bAce.RightName = "WriteProperty";
                        bAce.AceType = "AddMember";
                        yield return bAce;
                    }else if (objectType == Label.Computer && aceType == "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79")
                    {
                        bAce.RightName = "WriteProperty";
                        bAce.AceType = "AddAllowedToAct";
                        yield return bAce;
                    }
                }
            }
        }
        
        /// <summary>
        /// Helper function to determine if an ACE actually applies to the object through inheritance
        /// </summary>
        /// <param name="ace"></param>
        /// <param name="guid"></param>
        /// <returns></returns>
        private static bool IsAceInherited(ObjectAccessRule ace, string guid)
        {
            //Check if the ace is inherited
            var isInherited = ace.IsInherited;

            //The inheritedobjecttype needs to match the guid of the object type being enumerated or the guid for All
            var inheritedType = ace.InheritedObjectType.ToString();
            isInherited = isInherited && (inheritedType == AllGuid || inheritedType == guid);

            //Special case for Exchange
            //If the ACE is not Inherited and is not an inherit-only ace, then it's set by exchange for reasons
            if (!isInherited && (ace.PropagationFlags & PropagationFlags.InheritOnly) != PropagationFlags.InheritOnly &&
                !ace.IsInherited)
            {
                isInherited = true;
            }

            //Return our isInherited value
            return isInherited;
        }

        /// <summary>
        /// Processes the msds-groupmsamembership property and returns ACEs representing principals that can read the GMSA password from an object
        /// </summary>
        /// <param name="groupMSAMembership">The raw bytes representing the groupMSAMembership value</param>
        /// <param name="objectDomain">The domain of the object the property is coming from</param>
        /// <returns>An enumerable containing ACEs that allow reading the GMSA password</returns>
        public static IEnumerable<ACE> ProcessGMSAReaders(SearchResultEntry entry, string objectDomain)
        {
            var groupMSAMembership = entry.GetPropertyAsBytes("msds-groupmsamembership");
            if (groupMSAMembership == null)
                yield break;

            var descriptor = new ActiveDirectorySecurity();
            descriptor.SetSecurityDescriptorBinaryForm(groupMSAMembership);

            foreach (ActiveDirectoryAccessRule ace in descriptor.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (ace == null)
                    continue;
                
                if (ace.AccessControlType == AccessControlType.Deny)
                    continue;

                var principalSid = PreProcessSID(ace.IdentityReference.Value);
                
                if (principalSid == null)
                    continue;

                var instance = LDAPUtils.Instance;

                var resolvedPrincipal = instance.ResolveSidAndType(principalSid, objectDomain);
                
                yield return new ACE
                {
                    RightName = "ReadGMSAPassword",
                    AceType = "",
                    PrincipalType = resolvedPrincipal.ObjectType,
                    PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                    IsInherited = ace.IsInherited
                };
            }
        }

        private static string PreProcessSID(string sid)
        {
            if (sid != null)
            {
                //Ignore Local System/Creator Owner/Principal Self
                return sid is "S-1-5-18" or "S-1-3-0" or "S-1-5-10" ? null : sid.ToUpper();    
            }

            return null;
        }
    }
}