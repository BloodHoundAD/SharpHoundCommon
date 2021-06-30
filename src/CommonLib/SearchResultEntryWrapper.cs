using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Security.Principal;
using System.Threading.Tasks;
using SharpHoundCommonLib.Enums;

namespace SharpHoundCommonLib
{
    public interface ISearchResultEntry
    {
        string DistinguishedName { get; }
        Task<ResolvedSearchResult> ResolveBloodHoundInfo();
        string GetProperty(string propertyName);
        byte[] GetByteProperty(string propertyName);
        string[] GetArrayProperty(string propertyName);
        byte[][] GetByteArrayProperty(string propertyName);
        string GetObjectIdentifier();
        bool IsDeleted();
        Label GetLabel();
        string GetSid();
        string GetGuid();
        int PropCount(string prop);
        IEnumerable<string> PropertyNames();
    }

    public class SearchResultEntryWrapper : ISearchResultEntry
    {
        private readonly SearchResultEntry _entry;
        private readonly ILDAPUtils _utils;

        public SearchResultEntryWrapper(SearchResultEntry entry, ILDAPUtils utils = null)
        {
            _entry = entry;
            _utils = utils ?? new LDAPUtils();
        }

        public string DistinguishedName => _entry.DistinguishedName;

        public async Task<ResolvedSearchResult> ResolveBloodHoundInfo()
        {
            var res = new ResolvedSearchResult();

            var itemID = GetObjectIdentifier();
            if (itemID == null)
                return null;

            res.ObjectId = itemID;
            if (IsDeleted())
            {
                res.Deleted = IsDeleted();
                return res;
            }

            //Try to resolve the domain
            var distinguishedName = DistinguishedName;
            string itemDomain;
            if (distinguishedName == null)
            {
                if (itemID.StartsWith("S-1-"))
                {
                    itemDomain = _utils.GetDomainNameFromSid(itemID);
                }
                else
                {
                    return null;
                }
            }
            else
            {
                itemDomain = Helpers.DistinguishedNameToDomain(distinguishedName);
            }
            
            res.Domain = itemDomain;

            if (WellKnownPrincipal.GetWellKnownPrincipal(itemID, out var wkPrincipal))
            {
                res.DomainSid = await _utils.GetSidFromDomainName(itemDomain);
                res.DisplayName = $"{wkPrincipal.ObjectIdentifier}@{itemDomain}";
                res.ObjectType = wkPrincipal.ObjectType;
                res.ObjectId = _utils.ConvertWellKnownPrincipal(itemID, itemDomain);

                return res;
            }

            if (itemID.StartsWith("S-1-"))
            {
                res.DomainSid = new SecurityIdentifier(itemID).AccountDomainSid.Value;
            }
            else
            {
                res.DomainSid = await _utils.GetSidFromDomainName(itemDomain);
            }


            var samAccountName = GetProperty("samaccountname");

            var itemType = GetLabel();
            res.ObjectType = itemType;

            switch (itemType)
            {
                case Label.User:
                case Label.Group:
                    res.DisplayName = $"{samAccountName}@{itemDomain}";
                    break;
                case Label.Computer:
                    var shortName = samAccountName?.TrimEnd('$');
                    var dns = GetProperty("dnshostname");
                    var cn = GetProperty("cn");

                    //If we have this object class, override the object type
                    if (GetArrayProperty("objectclass").Contains("msds-groupmanagedserviceaccount",
                        StringComparer.InvariantCultureIgnoreCase))
                    {
                        res.ObjectType = Label.User;
                    }

                    if (dns != null)
                    {
                        res.DisplayName = dns;
                    }
                    else
                    {
                        if (shortName == null && cn == null)
                            res.DisplayName = $"UNKNOWN.{itemDomain}";
                        else if (shortName != null)
                            res.DisplayName = $"{shortName}.{itemDomain}";
                        else
                            res.DisplayName = $"{cn}.{itemDomain}";
                    }

                    break;
                case Label.GPO:
                    res.DisplayName = $"{GetProperty("displayname")}@{itemDomain}";
                    break;
                case Label.Domain:
                    res.DisplayName = itemDomain;
                    break;
                case Label.OU:
                case Label.Container:
                    res.DisplayName = $"{GetProperty("name")}@{itemDomain}";
                    break;
                case Label.Base:
                    res.DisplayName = $"{samAccountName}@{itemDomain}";
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }
            
            return res;
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

        public int PropCount(string prop)
        {
            var coll = _entry.Attributes[prop];
            return coll.Count;
        }

        public IEnumerable<string> PropertyNames()
        {
            foreach (var property in _entry.Attributes.AttributeNames)
            {
                yield return property.ToString().ToLower();
            }
        }

        public SearchResultEntry GetEntry()
        {
            return _entry;
        }
    }
}