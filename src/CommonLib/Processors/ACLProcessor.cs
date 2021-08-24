using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;

namespace SharpHoundCommonLib.Processors
{
    public class ACLProcessor
    {
        private static readonly Dictionary<Label, string> BaseGuids;
        private static readonly ConcurrentDictionary<string, string> GuidMap = new();
        private static bool _isCacheBuilt;
        private readonly ILDAPUtils _utils;

        static ACLProcessor()
        {
            //Create a dictionary with the base GUIDs of each object type
            BaseGuids = new Dictionary<Label, string>
            {
                {Label.User, "bf967aba-0de6-11d0-a285-00aa003049e2"},
                {Label.Computer, "bf967a86-0de6-11d0-a285-00aa003049e2"},
                {Label.Group, "bf967a9c-0de6-11d0-a285-00aa003049e2"},
                {Label.Domain, "19195a5a-6da0-11d0-afd3-00c04fd930c9"},
                {Label.GPO, "f30e3bc2-9ff0-11d1-b603-0000f80367c1"},
                {Label.OU, "bf967aa5-0de6-11d0-a285-00aa003049e2"},
                {Label.Container, "bf967a8b-0de6-11d0-a285-00aa003049e2"}
            };
        }

        public ACLProcessor(ILDAPUtils utils, bool noGuidCache = false)
        {
            _utils = utils;
            if (!noGuidCache)
                BuildGUIDCache();
        }

        /// <summary>
        ///     Builds a mapping of GUID -> Name for LDAP rights. Used for rights that are created using an extended schema such as
        ///     LAPS
        /// </summary>
        private void BuildGUIDCache()
        {
            if (_isCacheBuilt)
                return;

            var forest = _utils.GetForest();
            if (forest == null)
            {
                Logging.Log(LogLevel.Error, "Unable to resolve forest for GUID cache");
                return;
            }

            var schema = forest.Schema?.Name;
            if (string.IsNullOrEmpty(schema))
                return;
            foreach (var entry in _utils.QueryLDAP("(schemaIDGUID=*)", SearchScope.Subtree,
                new[] {"schemaidguid", "name"}, adsPath: schema))
            {
                var name = entry.GetProperty("name")?.ToLower();
                var guid = new Guid(entry.GetByteProperty("schemaidguid")).ToString();
                GuidMap.TryAdd(guid, name);
            }

            _isCacheBuilt = true;
        }

        /// <summary>
        ///     Gets the protection state of the access control list
        /// </summary>
        /// <param name="ntSecurityDescriptor"></param>
        /// <returns></returns>
        public bool IsACLProtected(byte[] ntSecurityDescriptor)
        {
            if (ntSecurityDescriptor == null)
                return false;

            var descriptor = _utils.MakeSecurityDescriptor();
            descriptor.SetSecurityDescriptorBinaryForm(ntSecurityDescriptor);

            return descriptor.AreAccessRulesProtected();
        }

        /// <summary>
        ///     Read's the ntSecurityDescriptor from a SearchResultEntry and processes the ACEs in the ACL, filtering out ACEs that
        ///     BloodHound is not interested in
        /// </summary>
        /// <param name="ntSecurityDescriptor"></param>
        /// <param name="objectDomain"></param>
        /// <param name="objectType"></param>
        /// <param name="hasLaps"></param>
        /// <returns></returns>
        public IEnumerable<ACE> ProcessACL(byte[] ntSecurityDescriptor, string objectDomain, Label objectType,
            bool hasLaps)
        {
            if (ntSecurityDescriptor == null)
            {
                Logging.Log(LogLevel.Debug, "ProcessACL received null ntSecurityDescriptor");
                yield break;
            }

            var descriptor = _utils.MakeSecurityDescriptor();
            descriptor.SetSecurityDescriptorBinaryForm(ntSecurityDescriptor);

            var ownerSid = Helpers.PreProcessSID(descriptor.GetOwner(typeof(SecurityIdentifier)));

            if (ownerSid != null)
            {
                var resolvedOwner = _utils.ResolveIDAndType(ownerSid, objectDomain);
                if (resolvedOwner != null)
                    yield return new ACE
                    {
                        PrincipalType = resolvedOwner.ObjectType,
                        PrincipalSID = resolvedOwner.ObjectIdentifier,
                        RightName = EdgeNames.Owns,
                        IsInherited = false
                    };
            }
            else
            {
                Logging.Log(LogLevel.Debug, "Owner on ACE is null");
            }

            foreach (var ace in descriptor.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (ace == null)
                {
                    Logging.Trace("Skipping null ACE");
                    continue;
                }

                if (ace.AccessControlType() == AccessControlType.Deny)
                {
                    Logging.Trace("Skipping deny ACE");
                    continue;
                }

                if (!ace.IsAceInheritedFrom(BaseGuids[objectType]))
                {
                    Logging.Trace("Skipping ACE with unmatched GUID/inheritance");
                    continue;
                }

                var principalSid = Helpers.PreProcessSID(ace.IdentityReference());

                if (principalSid == null)
                {
                    Logging.Trace("Pre-Process excluded SID");
                    continue;
                }

                var resolvedPrincipal = _utils.ResolveIDAndType(principalSid, objectDomain);

                var aceRights = ace.ActiveDirectoryRights();
                //Lowercase this just in case. As far as I know it should always come back that way anyways, but better safe than sorry
                var aceType = ace.ObjectType().ToString().ToLower();
                var inherited = ace.IsInherited();

                GuidMap.TryGetValue(aceType, out var mappedGuid);

                //GenericAll applies to every object
                if (aceRights.HasFlag(ActiveDirectoryRights.GenericAll))
                {
                    if (aceType is ACEGuids.AllGuid or "")
                        yield return new ACE
                        {
                            PrincipalType = resolvedPrincipal.ObjectType,
                            PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                            IsInherited = inherited,
                            RightName = EdgeNames.GenericAll
                        };
                    //This is a special case. If we don't continue here, every other ACE will match because GenericAll includes all other permissions
                    continue;
                }

                //WriteDACL and WriteOwner are always useful no matter what the object type is as well because they enable all other attacks
                if (aceRights.HasFlag(ActiveDirectoryRights.WriteDacl))
                    yield return new ACE
                    {
                        PrincipalType = resolvedPrincipal.ObjectType,
                        PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                        IsInherited = inherited,
                        RightName = EdgeNames.WriteDacl
                    };

                if (aceRights.HasFlag(ActiveDirectoryRights.WriteOwner))
                    yield return new ACE
                    {
                        PrincipalType = resolvedPrincipal.ObjectType,
                        PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                        IsInherited = inherited,
                        RightName = EdgeNames.WriteOwner
                    };

                //Cool ACE courtesy of @rookuu. Allows a principal to add itself to a group and no one else
                if (aceRights.HasFlag(ActiveDirectoryRights.Self) &&
                    !aceRights.HasFlag(ActiveDirectoryRights.WriteProperty) &&
                    !aceRights.HasFlag(ActiveDirectoryRights.GenericWrite) && objectType == Label.Group &&
                    aceType == ACEGuids.WriteMember)
                    yield return new ACE
                    {
                        PrincipalType = resolvedPrincipal.ObjectType,
                        PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                        IsInherited = inherited,
                        RightName = EdgeNames.AddSelf
                    };

                //Process object type specific ACEs. Extended rights apply to users, domains, and computers
                if (aceRights.HasFlag(ActiveDirectoryRights.ExtendedRight))
                {
                    if (objectType == Label.Domain)
                    {
                        if (aceType == ACEGuids.DSReplicationGetChanges)
                            yield return new ACE
                            {
                                PrincipalType = resolvedPrincipal.ObjectType,
                                PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                IsInherited = inherited,
                                RightName = EdgeNames.GetChanges
                            };
                        else if (aceType == ACEGuids.DSReplicationGetChangesAll)
                            yield return new ACE
                            {
                                PrincipalType = resolvedPrincipal.ObjectType,
                                PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                IsInherited = inherited,
                                RightName = EdgeNames.GetChangesAll
                            };
                        else if (aceType is ACEGuids.AllGuid or "")
                            yield return new ACE
                            {
                                PrincipalType = resolvedPrincipal.ObjectType,
                                PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                IsInherited = inherited,
                                RightName = EdgeNames.AllExtendedRights
                            };
                    }
                    else if (objectType == Label.User)
                    {
                        if (aceType == ACEGuids.UserForceChangePassword)
                            yield return new ACE
                            {
                                PrincipalType = resolvedPrincipal.ObjectType,
                                PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                IsInherited = inherited,
                                RightName = EdgeNames.ForceChangePassword
                            };
                        else if (aceType is ACEGuids.AllGuid or "")
                            yield return new ACE
                            {
                                PrincipalType = resolvedPrincipal.ObjectType,
                                PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                IsInherited = inherited,
                                RightName = EdgeNames.AllExtendedRights
                            };
                    }
                    else if (objectType == Label.Computer)
                    {
                        //ReadLAPSPassword is only applicable if the computer actually has LAPS. Check the world readable property ms-mcs-admpwdexpirationtime
                        if (hasLaps)
                        {
                            if (aceType is ACEGuids.AllGuid or "")
                                yield return new ACE
                                {
                                    PrincipalType = resolvedPrincipal.ObjectType,
                                    PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                    IsInherited = inherited,
                                    RightName = EdgeNames.AllExtendedRights
                                };
                            else if (mappedGuid is "ms-mcs-admpwd")
                                yield return new ACE
                                {
                                    PrincipalType = resolvedPrincipal.ObjectType,
                                    PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                    IsInherited = inherited,
                                    RightName = EdgeNames.ReadLAPSPassword
                                };
                        }
                    }
                }

                //GenericWrite encapsulates WriteProperty, so process them in tandem to avoid duplicate edges
                if (aceRights.HasFlag(ActiveDirectoryRights.GenericWrite) ||
                    aceRights.HasFlag(ActiveDirectoryRights.WriteProperty))
                {
                    if (objectType is Label.User or Label.Group or Label.Computer or Label.GPO)
                        if (aceType is ACEGuids.AllGuid or "")
                            yield return new ACE
                            {
                                PrincipalType = resolvedPrincipal.ObjectType,
                                PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                IsInherited = inherited,
                                RightName = EdgeNames.GenericWrite
                            };

                    if (objectType == Label.User && aceType == ACEGuids.WriteSPN)
                        yield return new ACE
                        {
                            PrincipalType = resolvedPrincipal.ObjectType,
                            PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                            IsInherited = inherited,
                            RightName = EdgeNames.WriteSPN
                        };
                    else if (objectType == Label.Computer && aceType == ACEGuids.WriteAllowedToAct)
                        yield return new ACE
                        {
                            PrincipalType = resolvedPrincipal.ObjectType,
                            PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                            IsInherited = inherited,
                            RightName = EdgeNames.AddAllowedToAct
                        };
                    else if (objectType == Label.Group && aceType == ACEGuids.WriteMember)
                        yield return new ACE
                        {
                            PrincipalType = resolvedPrincipal.ObjectType,
                            PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                            IsInherited = inherited,
                            RightName = EdgeNames.AddMember
                        };
                    else if (objectType is Label.User or Label.Computer && aceType == ACEGuids.AddKeyPrincipal)
                        yield return new ACE
                        {
                            PrincipalType = resolvedPrincipal.ObjectType,
                            PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                            IsInherited = inherited,
                            RightName = EdgeNames.AddKeyCredentialLink
                        };
                }
            }
        }

        /// <summary>
        ///     Processes the msds-groupmsamembership property and returns ACEs representing principals that can read the GMSA
        ///     password from an object
        /// </summary>
        /// <param name="entry"></param>
        /// <param name="objectDomain"></param>
        /// <returns></returns>
        public IEnumerable<ACE> ProcessGMSAReaders(byte[] groupMSAMembership, string objectDomain)
        {
            if (groupMSAMembership == null)
                yield break;

            var descriptor = _utils.MakeSecurityDescriptor();
            descriptor.SetSecurityDescriptorBinaryForm(groupMSAMembership);

            foreach (var ace in descriptor.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (ace == null)
                    continue;

                if (ace.AccessControlType() == AccessControlType.Deny)
                    continue;

                var principalSid = Helpers.PreProcessSID(ace.IdentityReference());

                if (principalSid == null)
                    continue;

                var resolvedPrincipal = _utils.ResolveIDAndType(principalSid, objectDomain);

                if (resolvedPrincipal != null)
                    yield return new ACE
                    {
                        RightName = EdgeNames.ReadGMSAPassword,
                        PrincipalType = resolvedPrincipal.ObjectType,
                        PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                        IsInherited = ace.IsInherited()
                    };
            }
        }
    }
}