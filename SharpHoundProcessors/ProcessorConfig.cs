namespace SharpHoundProcessors {
    public class ProcessorConfig {
        //Computer Availability Arguments
        public int PortScanTimeout { get; set;}= 10000;
        public int ComputerExpiryDays { get; set; } = 60;
        public bool SkipPortScan { get; set; } = false;
        public bool SkipComputerAgeCheck { get; set; } = false;
        
        //Session Processor Arguments
        public bool UseAlternateLocalAdminCredentials { get; set; } = false;
        public string AlternateLocalAdminUsername { get; set; } = null;
        public string AlternateLocalAdminPassword { get; set; } = null;
        public string OverrideCurrentUserName { get; set; } = null;
    }
}