using CommonLibTest.Facades;
using SharpHoundCommonLib.OutputTypes;
using Xunit;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace SharpHoundCommonLib.Processors
{
    public class SPNProcessorsTest
    {
        [Fact]
        public async Task ReadSPNTargets_SPNLengthZero_YieldBreak()
        {
            var processor = new SPNProcessors(new MockLDAPUtils());
            string[] servicePrincipalNames = new string[0]; 
            string distingishedName = "cn=policies,cn=system,DC=testlab,DC=local";
            await foreach(var spn in processor.ReadSPNTargets(servicePrincipalNames, distingishedName)) {
                Assert.Null(spn);
            }
        }

        [Fact]
        public async Task ReadSPNTargets_NoPortSupplied_ParsedCorrectly()
        {
            var processor = new SPNProcessors(new MockLDAPUtils());
            string[] servicePrincipalNames = new[] { "MSSQLSvc/PRIMARY.TESTLAB.LOCAL" };
            string distingishedName = "cn=policies,cn=system,DC=testlab,DC=local";

            SPNTarget expected = new SPNTarget() { ComputerSID = "S-1-5-21-3130019616-2776909439-2417379446-1001", Port = 1433, Service = SPNService.MSSQL };

            await foreach (var actual in processor.ReadSPNTargets(servicePrincipalNames, distingishedName))
            {
                Assert.Equal(expected.ComputerSID, actual.ComputerSID);
                Assert.Equal(expected.Port, actual.Port);
                Assert.Equal(expected.Service, actual.Service);
            }
        }

        [Fact]
        public async Task ReadSPNTargets_BadPortSupplied_ParsedCorrectly()
        {
            var processor = new SPNProcessors(new MockLDAPUtils());
            string[] servicePrincipalNames = new[] { "MSSQLSvc/PRIMARY.TESTLAB.LOCAL:abcd" };
            string distingishedName = "cn=policies,cn=system,DC=testlab,DC=local";

            SPNTarget expected = new SPNTarget() { ComputerSID = "S-1-5-21-3130019616-2776909439-2417379446-1001", Port = 1433, Service = SPNService.MSSQL };

            await foreach (var actual in processor.ReadSPNTargets(servicePrincipalNames, distingishedName))
            {
                Assert.Equal(expected.ComputerSID, actual.ComputerSID);
                Assert.Equal(expected.Port, actual.Port);
                Assert.Equal(expected.Service, actual.Service);
            }
        }

        [Fact]
        public async void ReadSPNTargets_SuppliedPort_ParsedCorrectly() 
        {
            var processor = new SPNProcessors(new MockLDAPUtils());
            string[] servicePrincipalNames = new[] { "MSSQLSvc/PRIMARY.TESTLAB.LOCAL:2345" };
            string distingishedName = "cn=policies,cn=system,DC=testlab,DC=local";

            SPNTarget expected = new SPNTarget() { ComputerSID = "S-1-5-21-3130019616-2776909439-2417379446-1001", Port = 2345, Service = SPNService.MSSQL };

            await foreach (var actual in processor.ReadSPNTargets(servicePrincipalNames, distingishedName))
            {
                Assert.Equal(expected.ComputerSID, actual.ComputerSID);
                Assert.Equal(expected.Port, actual.Port);
                Assert.Equal(expected.Service, actual.Service);
            }
        }

        [Fact]
        public async void ReadSPNTargets_MissingMssqlSvc_NotRead() 
        {
            var processor = new SPNProcessors(new MockLDAPUtils());
            string[] servicePrincipalNames = new[] { "myhost.redmond.microsoft.com:1433" };
            string distingishedName = "CN=Jeff Smith,OU=Sales,DC=Fabrikam,DC=COM";
            await foreach(var spn in processor.ReadSPNTargets(servicePrincipalNames, distingishedName)) {
                Assert.Null(spn);
            }
        }

        [Fact]
        public async void ReadSPNTargets_SPNWithAddressSign_NotRead() 
        {
            var processor = new SPNProcessors(new MockLDAPUtils());
            string[] servicePrincipalNames = new[] { "MSSQLSvc/myhost.redmond.microsoft.com:1433 user@domain" };
            string distingishedName = "CN=Jeff Smith,OU=Sales,DC=Fabrikam,DC=COM";
            await foreach(var spn in processor.ReadSPNTargets(servicePrincipalNames, distingishedName)) {
                Assert.Null(spn);
            }
        }
    }
}