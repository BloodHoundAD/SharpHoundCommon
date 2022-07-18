using System;

namespace SharpHoundRPC.LSANative
{
    public class LSAEnums
    {
        [Flags]
        public enum LsaOpenMask
        {
            ViewLocalInfo = 0x1,
            ViewAuditInfo = 0x2,
            GetPrivateInfo = 0x4,
            TrustAdmin = 0x8,
            CreateAccount = 0x10,
            CreateSecret = 0x20,
            CreatePrivilege = 0x40,
            SetDefaultQuotaLimits = 0x80,
            SetAuditRequirements = 0x100,
            AuditLogAdmin = 0x200,
            ServerAdmin = 0x400,
            LookupNames = 0x800,
            Notification = 0x1000,
            POLICY_READ = 0x20006,
            POLICY_ALL_ACCESS = 0x00F0FFF,
            POLICY_EXECUTE = 0X20801,
            POLICY_WRITE = 0X207F8
        }

        public enum LSAPolicyInformation
        {
            PolicyAuditLogInformation = 1,
            PolicyAuditEventsInformation,
            PolicyPrimaryDomainInformation,
            PolicyPdAccountInformation,
            PolicyAccountDomainInformation,
            PolicyLsaServerRoleInformation,
            PolicyReplicaSourceInformation,
            PolicyDefaultQuotaInformation,
            PolicyModificationInformation,
            PolicyAuditFullSetInformation,
            PolicyAuditFullQueryInformation,
            PolicyDnsDomainInformation
        }
    }
}