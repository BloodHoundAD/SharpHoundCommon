using System;
using System.Threading.Tasks;

namespace SharpHoundProcessors {
    public class ProcessorConfig {
        private static readonly Lazy<Random> RandomGen = new();
        //Computer Availability Arguments
        public int PortScanTimeout { get; set;}= 10000;
        public int ComputerExpiryDays { get; set; } = 60;
        public bool SkipPortScan { get; set; } = false;
        public bool SkipComputerAgeCheck { get; set; } = false;
        public string DNSName { get; set; } = null;
        
        //Session Processor Arguments
        public bool UseAlternateLocalAdminCredentials { get; set; } = false;
        public string AlternateLocalAdminUsername { get; set; } = null;
        public string AlternateLocalAdminPassword { get; set; } = null;
        public string OverrideCurrentUserName { get; set; } = null;
        public bool SkipRegistryLoggedOn { get; set; } = false;
        
        //Ldap Property Processor
        public bool CollectAllProperties { get; set; } = false;
        
        //Throttle
        public int Throttle { get; set; } = 0;
        public int Jitter { get; set; } = 0;
        
        public async Task Delay()
        {
            if (Throttle == 0)
                return;

            if (Jitter == 0)
            {
                await Task.Delay(Throttle);
                return;
            }

            var percent = (int)Math.Floor((double)(Jitter * (Throttle / 100)));
            var delay = Throttle + RandomGen.Value.Next(-percent, percent);
            await Task.Delay(delay);
        }
    }
}