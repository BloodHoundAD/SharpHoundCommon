using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CommonLib.Enums;

namespace CommonLib
{
    /// <summary>
    /// 
    /// </summary>
    public interface ICliConsoleFacade 
    {
        void WriteLine(string message = null);
    }

    /// <summary>
    /// 
    /// </summary>
    /// <typeparam name="CollectionMethodResolved"></typeparam>
    public abstract class CliBaseClient<CollectionMethodResolved> where CollectionMethodResolved : class
    {
        private ICliConsoleFacade _console;
        private Options<CollectionMethodResolved> _options;
        private bool _initialCompleted = false;
        private bool _needsCancellation = false;
        private Timer _timer = null;
        private DateTime _loopEnd = DateTime.Now;

        public CliBaseClient(ICliConsoleFacade console) => _console = console;

        public void Init(Options<CollectionMethodResolved> o) {

            var currentTime = DateTime.Now;
            var initString =
                $"Initializing SharpHound at {currentTime.ToShortTimeString()} on {currentTime.ToShortDateString()}";
            _console.WriteLine(new string('-', initString.Length));
            _console.WriteLine(initString);
            _console.WriteLine(new string('-', initString.Length));
            _console.WriteLine(String.Empty);

            // Set the current user name for session collection.
            if (o.OverrideUserName != null)
            {
                o.CurrentUserName = o.OverrideUserName;
            }
            else
            {
                o.CurrentUserName = WindowsIdentity.GetCurrent().Name.Split('\\')[1];
            }

            //Check some loop options
            if (o.Loop)
            {
                //If loop is set, ensure we actually set options properly
                if (o.LoopDuration == TimeSpan.Zero)
                {
                    _console.WriteLine("Loop specified without a duration. Defaulting to 2 hours!");
                    o.LoopDuration = TimeSpan.FromHours(2);
                }

                if (o.LoopInterval == TimeSpan.Zero)
                {
                    o.LoopInterval = TimeSpan.FromSeconds(30);
                }
            }

            _options = o;

            if (_options == null)
                return;

            // Check to make sure we actually have valid collection methods set
            if (!_options.ResolveCollectionMethods())
            {
                return;
            }

            //If the user didn't specify a domain, pull the domain from DirectoryServices
            if (_options.Domain == null) 
            {
                try
                {
                    _options.Domain = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain().Name.ToUpper();
                }
                catch (Exception e)
                {
                    _console.WriteLine(e.Message);
                    _console.WriteLine("Unable to determine user's domain. Please manually specify it with the --domain flag");
                    return;
                }
            }

            //Check to make sure both LDAP options are set if either is set
            if ((_options.LdapPassword != null && _options.LdapUsername == null) ||
                (_options.LdapUsername != null && _options.LdapPassword == null))
            {
                _console.WriteLine("You must specify both LdapUsername and LdapPassword if using these options!");
                return;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="options"></param>
        /// <returns></returns>
        public abstract Task Start<T>(Options<T> options);

        //Initial LDAP connection test. Search for the well known administrator SID to make sure we can connect successfully.
        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public virtual Task LDAPConnectionTest() 
        {
            return new Task(() => _console.WriteLine("--replace with custom implementation."));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public virtual Task CheckCancellation()
        {
            return new Task(() => _console.WriteLine("--replace with custom implementation"));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public virtual Task MainLoop()
        {
            return new Task(() => _console.WriteLine("--replace with custom implementation"));
        }
    }
}