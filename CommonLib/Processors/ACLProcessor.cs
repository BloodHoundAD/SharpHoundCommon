using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Security.AccessControl;
using System.Security.Principal;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;

namespace SharpHoundCommonLib.Processors
{
    public static class ACLProcessor
    {
        private static readonly Dictionary<Type, string> BaseGuids;
        private static readonly ConcurrentDictionary<string, string> GuidMap = new();
        
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

        /// <summary>
        /// Builds a mapping of GUID -> Name for LDAP rights. Used for rights that are created using an extended schema such as LAPS
        /// </summary>
        internal static void BuildGUIDCache()
        {
            var forest = LDAPUtils.GetForest();
            if (forest == null)
                return;

            var schema = forest.Schema.Name;
            foreach (var entry in LDAPUtils.QueryLDAP("(schemaIDGUID=*)", SearchScope.Subtree,
                new[] {"schemaidguid", "name"}, adsPath: schema))
            {
                var name = entry.GetProperty("name")?.ToLower();
                var guid = new Guid(entry.GetPropertyAsBytes("schemaidguid")).ToString();
                GuidMap.TryAdd(guid, name);
            }
        }

        /// <summary>
        /// Gets the protection state 
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public static bool IsACLProtected(SearchResultEntry entry)
        {
            var ntSecurityDescriptor = entry.GetPropertyAsBytes("ntsecuritydescriptor");
            if (ntSecurityDescriptor == null)
                return false;
            
            var descriptor = new ActiveDirectorySecurity();
            descriptor.SetSecurityDescriptorBinaryForm(ntSecurityDescriptor);

            return descriptor.AreAccessRulesProtected;
        }

        /// <summary>
        /// Read's the ntSecurityDescriptor from a SearchResultEntry and processes the ACEs in the ACL, filtering out ACEs that BloodHound is not interested in
        /// </summary>
        /// <param name="entry"></param>
        /// <param name="objectDomain"></param>
        /// <param name="objectType"></param>
        /// <returns></returns>
        public static IEnumerable<ACE> ProcessACL(SearchResultEntry entry, string objectDomain, Label objectType)
        {
            var ntSecurityDescriptor = entry.GetPropertyAsBytes("ntsecuritydescriptor");
            if (ntSecurityDescriptor == null)
                yield break;
            
            var descriptor = new ActiveDirectorySecurity();
            descriptor.SetSecurityDescriptorBinaryForm(ntSecurityDescriptor);

            var ownerSid = PreProcessSID(descriptor.GetOwner(typeof(SecurityIdentifier)).Value);

            if (ownerSid != null)
            {
                var resolvedOwner = LDAPUtils.ResolveIDAndType(ownerSid, objectDomain);
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

                var resolvedPrincipal = LDAPUtils.ResolveIDAndType(principalSid, objectDomain);

                var aceRights = ace.ActiveDirectoryRights;
                //Lowercase this just in case. As far as I know it should always come back that way anyways, but better safe than sorry
                var aceType = ace.ObjectType.ToString().ToLower();
                var inherited = ace.IsInherited;

                GuidMap.TryGetValue(aceType, out var mappedGuid);

                var bAce = new ACE
                {
                    PrincipalType = resolvedPrincipal.ObjectType,
                    PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                    IsInherited = inherited,
                };

                //GenericAll applies to every object
                if (aceRights.HasFlag(ActiveDirectoryRights.GenericAll))
                {
                    if (aceType is ACEGuids.AllGuid or "")
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
                
                //Cool ACE courtesy of @rookuu. Allows a principal to add itself to a group and no one else
                if (aceRights.HasFlag(ActiveDirectoryRights.Self))
                {
                    if (objectType == Label.Group)
                    {
                        if (aceType == ACEGuids.AddSelfToGroup)
                        {
                            bAce.RightName = "WriteProperty";
                            bAce.AceType = "AddSelf";
                            yield return bAce;
                        }
                    }
                }
                
                //Process object type specific ACEs. Extended rights apply to users, domains, and computers
                if (aceRights.HasFlag(ActiveDirectoryRights.ExtendedRight))
                {
                    if (objectType == Label.Domain)
                    {
                        if (aceType == ACEGuids.DSReplicationGetChanges)
                        {
                            bAce.RightName = "ExtendedRight";
                            bAce.AceType = "GetChanges";
                            yield return bAce;
                        }else if (aceType == ACEGuids.DSReplicationGetChangesAll){
                            bAce.RightName = "ExtendedRight";
                            bAce.AceType = "GetChangesAll";
                            yield return bAce;
                        }else if (aceType is ACEGuids.AllGuid or "")
                        {
                            bAce.RightName = "ExtendedRight";
                            bAce.AceType = "All";
                            yield return bAce;
                        }
                    }else if (objectType == Label.User){
                        if (aceType == ACEGuids.UserForceChangePassword){
                            bAce.RightName = "ForceChangePassword";
                            bAce.AceType = "GetChangesAll";
                            yield return bAce;
                        }else if (aceType is ACEGuids.AllGuid or ""){
                            bAce.RightName = "ExtendedRight";
                            bAce.AceType = "All";
                            yield return bAce;
                        }
                    }else if (objectType == Label.Computer){
                        //ReadLAPSPassword is only applicable if the computer actually has LAPS. Check the world readable property ms-mcs-admpwdexpirationtime
                        if (entry.GetProperty("ms-mcs-admpwdexpirationtime") != null)
                        {
                            if (aceType is ACEGuids.AllGuid or ""){
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
                        if (aceType is ACEGuids.AllGuid or "")
                        {
                            bAce.RightName = "GenericWrite";
                            bAce.AceType = "";
                            yield return bAce;
                        }
                    }

                    if (objectType == Label.User && aceType == ACEGuids.WriteMember)
                    {
                        bAce.RightName = "WriteProperty";
                        bAce.AceType = "AddMember";
                        yield return bAce;
                    }else if (objectType == Label.Computer && aceType == ACEGuids.WriteAllowedToAct)
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
            isInherited = isInherited && (inheritedType == ACEGuids.AllGuid || inheritedType == guid);

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
        /// <param name="entry"></param>
        /// <param name="objectDomain"></param>
        /// <returns></returns>
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
                
                var resolvedPrincipal = LDAPUtils.ResolveIDAndType(principalSid, objectDomain);
                
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

        /// <summary>
        /// Removes some commonly seen SIDs that have no use in the schema
        /// </summary>
        /// <param name="sid"></param>
        /// <returns></returns>
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