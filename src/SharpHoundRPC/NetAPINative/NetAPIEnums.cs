using System;

namespace SharpHoundRPC.NetAPINative
{
    public class NetAPIEnums
    {
        [Flags]
        public enum DSGETDCNAME_FLAGS : uint
        {
            DS_FORCE_REDISCOVERY = 0x00000001,
            DS_DIRECTORY_SERVICE_REQUIRED = 0x00000010,
            DS_DIRECTORY_SERVICE_PREFERRED = 0x00000020,
            DS_GC_SERVER_REQUIRED = 0x00000040,
            DS_PDC_REQUIRED = 0x00000080,
            DS_BACKGROUND_ONLY = 0x00000100,
            DS_IP_REQUIRED = 0x00000200,
            DS_KDC_REQUIRED = 0x00000400,
            DS_TIMESERV_REQUIRED = 0x00000800,
            DS_WRITABLE_REQUIRED = 0x00001000,
            DS_GOOD_TIMESERV_PREFERRED = 0x00002000,
            DS_AVOID_SELF = 0x00004000,
            DS_ONLY_LDAP_NEEDED = 0x00008000,
            DS_IS_FLAT_NAME = 0x00010000,
            DS_IS_DNS_NAME = 0x00020000,
            DS_RETURN_DNS_NAME = 0x40000000,
            DS_RETURN_FLAT_NAME = 0x80000000
        }

        public enum NetAPIStatus : uint
        {
            Success = 0,

            /// <summary>
            ///     This computer name is invalid.
            /// </summary>
            InvalidComputer = 2351,

            /// <summary>
            ///     This operation is only allowed on the primary domain controller of the domain.
            /// </summary>
            NotPrimary = 2226,

            /// <summary>
            ///     This operation is not allowed on this special group.
            /// </summary>
            SpeGroupOp = 2234,

            /// <summary>
            ///     This operation is not allowed on the last administrative account.
            /// </summary>
            LastAdmin = 2452,

            /// <summary>
            ///     The password parameter is invalid.
            /// </summary>
            BadPassword = 2203,

            /// <summary>
            ///     The password does not meet the password policy requirements.
            ///     Check the minimum password length, password complexity and password history requirements.
            /// </summary>
            PasswordTooShort = 2245,

            /// <summary>
            ///     The user name could not be found.
            /// </summary>
            UserNotFound = 2221,
            ErrorAccessDenied = 5,
            ErrorNotEnoughMemory = 8,
            ErrorInvalidParameter = 87,
            ErrorInvalidName = 123,
            ErrorInvalidLevel = 124,
            ErrorMoreData = 234,
            ErrorSessionCredentialConflict = 1219,

            /// <summary>
            ///     The RPC server is not available. This error is returned if a remote computer was specified in
            ///     the lpServer parameter and the RPC server is not available.
            /// </summary>
            RpcSServerUnavailable = 2147944122, // 0x800706BA

            /// <summary>
            ///     Remote calls are not allowed for this process. This error is returned if a remote computer was
            ///     specified in the lpServer parameter and remote calls are not allowed for this process.
            /// </summary>
            RpcERemoteDisabled = 2147549468 // 0x8001011C
        }
    }
}