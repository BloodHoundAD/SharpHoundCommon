using System.Security.Cryptography;
using SharpHoundCommonLib.Enums;

namespace SharpHoundCommonLib.OutputTypes
{
    public class CertTemplate : OutputBase
    {
        public int SchemaVersion { get; set; }
        public string ValidityPeriod { get; set; }
        public string RenewalPeriod { get; set; }
        public Oid TemplateOid { get; set; }
        public PKIEnrollmentFlag EnrollmentFlags { get; set; }
        public PKICertificateNameFlag CertificateNameFlags { get; set; }
        public string[] ExtendedKeyUsages { get; set; }
        public int AuthorizedSignatures { get; set; }
        public string[] ApplicationPolicies { get; set; }
        public string[] IssuancePolicies { get; set; }
    }
}