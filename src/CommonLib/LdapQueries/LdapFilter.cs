﻿using System.Collections.Generic;
using System.Linq;

namespace SharpHoundCommonLib.LDAPQueries {
    /// <summary>
    ///     A class used to more easily build LDAP filters based on the common filters used by SharpHound
    /// </summary>
    public class LdapFilter {
        private readonly List<string> _filterParts = new();
        private readonly List<string> _mandatory = new();

        /// <summary>
        ///     Pre-filters conditions passed into filters. Will fix filters that are missing parentheses naively
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        private static string[] CheckConditions(IEnumerable<string> conditions) {
            return conditions.Select(FixFilter).ToArray();
        }

        private static string FixFilter(string filter) {
            if (!filter.StartsWith("(")) filter = $"({filter}";

            if (!filter.EndsWith(")")) filter = $"{filter})";

            return filter;
        }

        /// <summary>
        ///     Takes a base filter and appends any number of LDAP conditionals in a LDAP "And" statement.
        ///     Returns the base filter if no extra conditions are specified
        /// </summary>
        /// <param name="baseFilter"></param>
        /// <param name="conditions"></param>
        /// <returns></returns>
        private static string BuildString(string baseFilter, params string[] conditions) {
            if (conditions.Length == 0) return baseFilter;

            return $"(&{baseFilter}{string.Join("", CheckConditions(conditions))})";
        }

        /// <summary>
        ///     Add a wildcard filter will match all object types
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LdapFilter AddAllObjects(params string[] conditions) {
            _filterParts.Add(BuildString("(objectclass=*)", conditions));

            return this;
        }

        /// <summary>
        ///     Add a filter that will match User objects
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LdapFilter AddUsers(params string[] conditions) {
            _filterParts.Add(BuildString("(samaccounttype=805306368)", conditions));

            return this;
        }

        /// <summary>
        ///     Add a filter that will match Group objects
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LdapFilter AddGroups(params string[] conditions) {
            _filterParts.Add(BuildString(
                "(|(samaccounttype=268435456)(samaccounttype=268435457)(samaccounttype=536870912)(samaccounttype=536870913))",
                conditions));

            return this;
        }

        /// <summary>
        ///     Add a filter that will include any object with a primary group
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LdapFilter AddPrimaryGroups(params string[] conditions) {
            _filterParts.Add(BuildString("(primarygroupid=*)", conditions));

            return this;
        }

        /// <summary>
        ///     Add a filter that will include GPO objects
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LdapFilter AddGPOs(params string[] conditions) {
            _filterParts.Add(BuildString("(&(objectcategory=groupPolicyContainer)(flags=*))", conditions));

            return this;
        }

        /// <summary>
        ///     Add a filter that will include OU objects
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LdapFilter AddOUs(params string[] conditions) {
            _filterParts.Add(BuildString("(objectcategory=organizationalUnit)", conditions));

            return this;
        }

        /// <summary>
        ///     Add a filter that will include Domain objects
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LdapFilter AddDomains(params string[] conditions) {
            _filterParts.Add(BuildString("(objectclass=domain)", conditions));

            return this;
        }

        /// <summary>
        ///     Add a filter that will include Container objects
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LdapFilter AddContainers(params string[] conditions) {
            _filterParts.Add(BuildString("(objectClass=container)", conditions));

            return this;
        }

        /// <summary>
        ///     Add a filter that will include Configuration objects
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LdapFilter AddConfiguration(params string[] conditions) {
            _filterParts.Add(BuildString("(objectClass=configuration)", conditions));

            return this;
        }

        /// <summary>
        ///     Add a filter that will include Computer objects
        ///
        ///     Note that gMSAs and sMSAs have this samaccounttype as well
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LdapFilter AddComputers(params string[] conditions) {
            _filterParts.Add(BuildString("(samaccounttype=805306369)", conditions));
            return this;
        }

        /// <summary>
        ///     Add a filter that will include PKI Certificate templates
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LdapFilter AddCertificateTemplates(params string[] conditions) {
            _filterParts.Add(BuildString("(objectclass=pKICertificateTemplate)", conditions));
            return this;
        }

        /// <summary>
        ///     Add a filter that will include Certificate Authorities
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LdapFilter AddCertificateAuthorities(params string[] conditions) {
            _filterParts.Add(BuildString("(objectClass=certificationAuthority)",
                conditions));
            return this;
        }

        /// <summary>
        ///     Add a filter that will include Enterprise Certificate Authorities
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LdapFilter AddEnterpriseCertificationAuthorities(params string[] conditions) {
            _filterParts.Add(BuildString("(objectCategory=pKIEnrollmentService)", conditions));
            return this;
        }

        /// <summary>
        ///     Add a filter that will include Issuance Policies
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LdapFilter AddIssuancePolicies(params string[] conditions) {
            _filterParts.Add(BuildString("(objectClass=msPKI-Enterprise-Oid)", conditions));
            return this;
        }

        /// <summary>
        ///     Add a filter that will include schema items
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LdapFilter AddSchemaID(params string[] conditions) {
            _filterParts.Add(BuildString("(schemaidguid=*)", conditions));
            return this;
        }

        /// <summary>
        ///     Add a filter that will include Computer objects but exclude gMSA and sMSA objects
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LdapFilter AddComputersNoMSAs(params string[] conditions) {
            _filterParts.Add(BuildString(
                "(&(samaccounttype=805306369)(!(objectclass=msDS-GroupManagedServiceAccount))(!(objectclass=msDS-ManagedServiceAccount)))",
                conditions));
            return this;
        }

        /// <summary>
        ///     Adds a generic user specified filter
        /// </summary>
        /// <param name="filter">LDAP Filter to add to query</param>
        /// <param name="enforce">If true, filter will be AND otherwise OR</param>
        /// <returns></returns>
        public LdapFilter AddFilter(string filter, bool enforce) {
            if (enforce)
                _mandatory.Add(FixFilter(filter));
            else
                _filterParts.Add(FixFilter(filter));

            return this;
        }

        /// <summary>
        ///     Combines all the specified parts of the LDAP filter and merges them into a single string
        /// </summary>
        /// <returns></returns>
        public string GetFilter() {
            var filterPartList = _filterParts.ToArray().Distinct();
            var mandatoryList = _mandatory.ToArray().Distinct();

            var filterPartsExceptMandatory = filterPartList.Except(mandatoryList).ToList();

            var filterPartsDistinct = string.Join("", filterPartsExceptMandatory);
            var mandatoryDistinct = string.Join("", mandatoryList);

            if (filterPartsExceptMandatory.Count == 1)
                filterPartsDistinct = filterPartsExceptMandatory[0];
            else if (filterPartsExceptMandatory.Count > 1)
                filterPartsDistinct = $"(|{filterPartsDistinct})";

            filterPartsDistinct = _mandatory.Count > 0
                ? $"(&{filterPartsDistinct}{mandatoryDistinct})"
                : filterPartsDistinct;

            return filterPartsDistinct;
        }

        public IEnumerable<string> GetFilterList() {
            return _filterParts.Distinct();
        }
    }
}