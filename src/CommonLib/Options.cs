using System;
using System.Collections.Generic;
using System.Linq;

namespace CommonLib
{
    /*
    / For attribute override info .@SEE: https://stackoverflow.com/a/21656196
    */
    public abstract class Options<CollectionMethodResolved>
    {
        
        
        public static Options<CollectionMethodResolved> Instance { get; set; }

        #region Collection Options

        /// <summary>
        /// Collection Methods: Container, Group, LocalGroup, GPOLocalGroup, Session, LoggedOn, ObjectProps, ACL, ComputerOnly, Trusts, Default, RDP, DCOM, DCOnly
        /// </summary>
        public IEnumerable<string> CollectionMethods { get; set; }

        /// <summary>
        /// Use Stealth Targetting/Enumeration Options
        /// </summary>
        public bool Stealth { get; set; }

        /// <summary>
        /// Specify domain for enumeration
        /// </summary>
        public string Domain { get; set; }

        /// <summary>
        /// Limit collection to Windows hosts only
        /// </summary>
        public bool WindowsOnly { get; set; }

        /// <summary>
        /// Path to textfile containing line seperated computer names/sids
        /// </summary>
        public string ComputerFile { get; set; }

        #endregion

        #region Output Options
        
        /// <summary>
        /// Don't output data from this run. Used for debugging purposes
        /// </summary>
        public bool NoOutput { get; set; }

        /// <summary>
        /// Folder to output files too
        /// </summary>
        public string OutputDirectory { get; set; }

        /// <summary>
        /// Prefix for output files
        /// </summary>
        public string OutputPrefix { get; set; }

        /// <summary>
        /// Output pretty(formatted) JSON
        /// </summary>
        public bool PrettyJson { get; set; }

        /// <summary>
        /// Filename for the cache file (defaults to b64 of machine sid)
        /// </summary>

        public string CacheFilename { get; set; }

        /// <summary>
        /// Randomize filenames for JSON files
        /// </summary>
        public bool RandomizeFilenames { get; set; }

        /// <summary>
        /// Filename for the Zip file
        /// </summary>
        public string ZipFilename { get; set; }

        /// <summary>
        ///  Don't save cache to disk. Caching will still be done in memory
        /// </summary>
        public bool NoSaveCache { get; set; }

        /// <summary>
        /// Encrypt zip file using a random password
        /// </summary>
        public bool EncryptZip { get; set; }

        /// <summary>
        /// Don't zip JSON files
        /// </summary>
        public bool NoZip { get; set; }

        /// <summary>
        /// Invalidate and rebuild the cache
        /// </summary>
        public bool InvalidateCache { get; set; }

        #endregion

        #region Connection Options

        /// <summary>
        /// Custom LDAP Filter to append to the search. Use this to filter collection
        /// </summary>
        public string LdapFilter { get; set; }

        /// <summary>
        /// Domain Controller to connect too. Specifying this value can result in data loss
        /// </summary>
        public string DomainController { get; set; }

        /// <summary>
        /// Port LDAP is running on. Defaults to 389/636 for LDAPS
        /// </summary>
        public int LdapPort { get; set; }

        /// <summary>
        /// Connect to LDAPS (LDAP SSL) instead of regular LDAP
        /// </summary>
        public bool SecureLDAP { get; set; }

        /// <summary>
        /// Disables Kerberos Signing/Sealing making LDAP traffic viewable
        /// </summary>
        public bool DisableKerberosSigning { get; set; }

        /// <summary>
        /// Username to use for LDAP
        /// </summary>
        public string LdapUsername { get; set; }

        /// <summary>
        /// Password to use for LDAP
        /// </summary>
        public string LdapPassword { get; set; }

        #endregion

        #region Enumeration Options
        
        /// <summary>
        /// Base DistinguishedName to start search at. Use this to limit your search. Equivalent to the old --OU option
        /// </summary>
        public string SearchBase { get; set; }

        /// <summary>
        /// Skip SMB port checks when connecting to computers
        /// </summary>
        public bool SkipPortScan { get; set; }

        /// <summary>
        /// Timeout for SMB port check
        /// </summary>
        public int PortScanTimeout { get; set; }

        /// <summary>
        /// Exclude domain controllers from enumeration (useful to avoid Microsoft ATP/ATA)
        /// </summary>
        public bool ExcludeDomainControllers { get; set; }

        /// <summary>
        /// Throttle requests to computers in milliseconds
        /// </summary>
        public int Throttle { get; set; }

        /// <summary>
        /// Jitter between requests to computers
        /// </summary>
        public int Jitter { get; set; }

        /// <summary>
        /// Override username to filter for NetSessionEnum
        /// </summary>
        public string OverrideUserName { get; set; }

        /// <summary>
        /// Disable remote registry check in LoggedOn collection
        /// </summary>
        public bool NoRegistryLoggedOn { get; set; }

        /// <summary>
        /// Dump success/failures related to computer enumeration to a CSV file
        /// </summary>
        public bool DumpComputerStatus { get; set; }

        /// <summary>
        /// Override DNS name for API calls
        /// </summary>
        public string RealDNSName { get; set; }

        /// <summary>
        /// Collect all LDAP properties from objects instead of a subset during ObjectProps
        /// </summary>
        public bool CollectAllProperties { get; set; }

        #endregion

        #region Console Output Options

        /// <summary>
        /// Interval in which to display status in milliseconds
        /// </summary>
        public int StatusInterval { get; set; }

        /// <summary>
        /// Enable Verbose Output
        /// </summary>
        public bool Verbose { get; set; }

        #endregion 

        #region Loop Options

        /// <summary>
        /// Loop Computer Collection
        /// </summary>
        public bool Loop { get; set; }

        /// <summary>
        /// Duration to perform looping (Default 02:00:00)
        /// </summary>
        public TimeSpan LoopDuration { get; set; }

        /// <summary>
        /// Interval to sleep between loops
        /// </summary>
        public TimeSpan LoopInterval { get; set; }

        #endregion

        #region Internal Options
        
        /// <summary>
        /// 
        /// </summary>
        internal CollectionMethodResolved ResolvedCollectionMethods { get; set; }

        
        /// <summary>
        /// 
        /// </summary>
        internal string CurrentUserName { get; set; }

        /// <summary>
        /// 
        /// </summary>
        internal abstract bool ResolveCollectionMethods();

        /// <summary>
        /// Removes non-computer collection methods from specified ones for looping
        /// </summary>
        /// <returns></returns>
        internal abstract CollectionMethodResolved GetLoopCollectionMethods();

        /// <summary>
        /// 
        /// </summary>
        internal abstract bool IsComputerCollectionSet();

        #endregion
    }
}
