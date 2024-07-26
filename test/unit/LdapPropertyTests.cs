using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using CommonLibTest.Facades;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.Processors;
using Xunit;
using Xunit.Abstractions;
// ReSharper disable StringLiteralTypo

namespace CommonLibTest
{
    public class LdapPropertyTests
    {
        private readonly ITestOutputHelper _testOutputHelper;

        public LdapPropertyTests(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        [Fact]
        public void LDAPPropertyProcessor_ReadDomainProperties_TestGoodData()
        {
            var mock = new MockDirectoryObject("DC\u003dtestlab,DC\u003dlocal", new Dictionary<string, object>
            {
                {"description", "TESTLAB Domain"},
                {"msds-behavior-version", "6"}
            }, "S-1-5-21-3130019616-2776909439-2417379446","");

            var test = LdapPropertyProcessor.ReadDomainProperties(mock);
            Assert.Contains("functionallevel", test.Keys);
            Assert.Equal("2012 R2", test["functionallevel"] as string);
            Assert.Contains("description", test.Keys);
            Assert.Equal("TESTLAB Domain", test["description"] as string);
        }

        [Fact]
        public void LDAPPropertyProcessor_ReadDomainProperties_TestBadFunctionalLevel()
        {
            var mock = new MockDirectoryObject("DC\u003dtestlab,DC\u003dlocal", new Dictionary<string, object>
            {
                {"msds-behavior-version", "a"}
            }, "S-1-5-21-3130019616-2776909439-2417379446","");

            var test = LdapPropertyProcessor.ReadDomainProperties(mock);
            Assert.Contains("functionallevel", test.Keys);
            Assert.Equal("Unknown", test["functionallevel"] as string);
        }

        [Fact]
        public void LDAPPropertyProcessor_FunctionalLevelToString_TestFunctionalLevels()
        {
            var expected = new Dictionary<int, string>
            {
                {0, "2000 Mixed/Native"},
                {1, "2003 Interim"},
                {2, "2003"},
                {3, "2008"},
                {4, "2008 R2"},
                {5, "2012"},
                {6, "2012 R2"},
                {7, "2016"},
                {-1, "Unknown"}
            };

            foreach (var (key, value) in expected)
                Assert.Equal(value, LdapPropertyProcessor.FunctionalLevelToString(key));
        }

        [Fact]
        public void LDAPPropertyProcessor_ReadGPOProperties_TestGoodData()
        {
            var mock = new MockDirectoryObject(
                "CN\u003d{94DD0260-38B5-497E-8876-10E7A96E80D0},CN\u003dPolicies,CN\u003dSystem,DC\u003dtestlab,DC\u003dlocal",
                new Dictionary<string, object>
                {
                    {
                        "gpcfilesyspath",
                        Utils.B64ToString(
                            "XFx0ZXN0bGFiLmxvY2FsXFN5c1ZvbFx0ZXN0bGFiLmxvY2FsXFBvbGljaWVzXHs5NEREMDI2MC0zOEI1LTQ5N0UtODg3Ni0xMEU3QTk2RTgwRDB9")
                    },
                    {"description", "Test"}
                }, "S-1-5-21-3130019616-2776909439-2417379446","");

            var test = LdapPropertyProcessor.ReadGPOProperties(mock);

            Assert.Contains("description", test.Keys);
            Assert.Equal("Test", test["description"] as string);
            Assert.Contains("gpcpath", test.Keys);
            Assert.Equal(@"\\TESTLAB.LOCAL\SYSVOL\TESTLAB.LOCAL\POLICIES\{94DD0260-38B5-497E-8876-10E7A96E80D0}",
                test["gpcpath"] as string);
        }

        [Fact]
        public void LDAPPropertyProcessor_ReadOUProperties_TestGoodData()
        {
            var mock = new MockDirectoryObject("OU\u003dTestOU,DC\u003dtestlab,DC\u003dlocal",
                new Dictionary<string, object>
                {
                    {"description", "Test"}
                },"", "2A374493-816A-4193-BEFD-D2F4132C6DCA");

            var test = LdapPropertyProcessor.ReadOUProperties(mock);
            Assert.Contains("description", test.Keys);
            Assert.Equal("Test", test["description"] as string);
        }

        [Fact]
        public void LDAPPropertyProcessor_ReadGroupProperties_TestGoodData()
        {
            var mock = new MockDirectoryObject("CN\u003dDomain Admins,CN\u003dUsers,DC\u003dtestlab,DC\u003dlocal",
                new Dictionary<string, object>
                {
                    {"description", "Test"},
                    {"admincount", "1"}
                }, "S-1-5-21-3130019616-2776909439-2417379446-512","");

            var test = LdapPropertyProcessor.ReadGroupProperties(mock);
            Assert.Contains("description", test.Keys);
            Assert.Equal("Test", test["description"] as string);
            Assert.Contains("admincount", test.Keys);
            Assert.True((bool)test["admincount"]);
        }

        [Fact]
        public void LDAPPropertyProcessor_ReadGroupProperties_TestGoodData_FalseAdminCount()
        {
            var mock = new MockDirectoryObject("CN\u003dDomain Admins,CN\u003dUsers,DC\u003dtestlab,DC\u003dlocal",
                new Dictionary<string, object>
                {
                    {"description", "Test"},
                    {"admincount", "0"}
                }, "S-1-5-21-3130019616-2776909439-2417379446-512","");

            var test = LdapPropertyProcessor.ReadGroupProperties(mock);
            Assert.Contains("description", test.Keys);
            Assert.Equal("Test", test["description"] as string);
            Assert.Contains("admincount", test.Keys);
            Assert.False((bool)test["admincount"]);
        }

        [Fact]
        public void LDAPPropertyProcessor_ReadGroupProperties_NullAdminCount()
        {
            var mock = new MockDirectoryObject("CN\u003dDomain Admins,CN\u003dUsers,DC\u003dtestlab,DC\u003dlocal",
                new Dictionary<string, object>
                {
                    {"description", "Test"}
                }, "S-1-5-21-3130019616-2776909439-2417379446-512","");

            var test = LdapPropertyProcessor.ReadGroupProperties(mock);
            Assert.Contains("description", test.Keys);
            Assert.Equal("Test", test["description"] as string);
            Assert.Contains("admincount", test.Keys);
            Assert.False((bool)test["admincount"]);
        }

        [Fact]
        public async Task LDAPPropertyProcessor_ReadUserProperties_TestTrustedToAuth()
        {
            var mock = new MockDirectoryObject("CN\u003ddfm,CN\u003dUsers,DC\u003dtestlab,DC\u003dlocal",
                new Dictionary<string, object>
                {
                    {"description", "Test"},
                    {"useraccountcontrol", 0x1000000.ToString()},
                    {LDAPProperties.LastLogon, "132673011142753043"},
                    {LDAPProperties.LastLogonTimestamp, "132670318095676525"},
                    {"homedirectory", @"\\win10\testdir"},
                    {
                        "serviceprincipalname", new[]
                        {
                            "MSSQLSVC\\win10"
                        }
                    },
                    {"admincount", "1"},
                    {
                        "sidhistory", new[]
                        {
                            Utils.B64ToBytes("AQUAAAAAAAUVAAAAIE+Qun9GhKV2SBaQUQQAAA==")
                        }
                    },
                    {"pwdlastset", "132131667346106691"},
                    {
                        "msds-allowedtodelegateto", new[]
                        {
                            "host/primary",
                            "rdpman/win10"
                        }
                    }
                }, "S-1-5-21-3130019616-2776909439-2417379446-1101", "");

            var processor = new LdapPropertyProcessor(new MockLdapUtils());
            var test = await processor.ReadUserProperties(mock, "testlab.local");
            var props = test.Props;
            var keys = props.Keys;

            Assert.Contains("allowedtodelegate", keys);
            var atd = props["allowedtodelegate"] as string[];
            Assert.Equal(2, atd.Length);
            Assert.Contains("host/primary", atd);
            Assert.Contains("rdpman/win10", atd);

            var atdr = test.AllowedToDelegate;
            Assert.Equal(2, atdr.Length);
            var expected = new TypedPrincipal[]
            {
                new()
                {
                    ObjectIdentifier = "S-1-5-21-3130019616-2776909439-2417379446-1001",
                    ObjectType = Label.Computer
                },
                new()
                {
                    ObjectIdentifier = "S-1-5-21-3130019616-2776909439-2417379446-1104",
                    ObjectType = Label.Computer
                }
            };
            Assert.Equal(expected, atdr);
        }

        [Fact]
        public async Task LDAPPropertyProcessor_ReadUserProperties_NullAdminCount()
        {
            var mock = new MockDirectoryObject("CN\u003ddfm,CN\u003dUsers,DC\u003dtestlab,DC\u003dlocal",
                new Dictionary<string, object>
                {
                    {"description", "Test"},
                    {"useraccountcontrol", "66048"},
                    {"lastlogon", "132673011142753043"},
                    {"lastlogontimestamp", "132670318095676525"},
                    {"homedirectory", @"\\win10\testdir"},
                    {
                        "serviceprincipalname", new[]
                        {
                            "MSSQLSVC\\win10"
                        }
                    },
                    {
                        "sidhistory", new[]
                        {
                            Utils.B64ToBytes("AQUAAAAAAAUVAAAAIE+Qun9GhKV2SBaQUQQAAA==")
                        }
                    },
                    {"pwdlastset", "132131667346106691"}
                }, "S-1-5-21-3130019616-2776909439-2417379446-1101","");

            var processor = new LdapPropertyProcessor(new MockLdapUtils());
            var test = await processor.ReadUserProperties(mock, "testlab.local");
            var props = test.Props;
            var keys = props.Keys;
            Assert.Contains("admincount", keys);
            Assert.False((bool)props["admincount"]);
        }

        [WindowsOnlyFact]
        public async Task LDAPPropertyProcessor_ReadUserProperties_HappyPath()
        {
            var mock = new MockDirectoryObject("CN\u003ddfm,CN\u003dUsers,DC\u003dtestlab,DC\u003dlocal",
                new Dictionary<string, object>
                {
                    {"description", "Test"},
                    {"useraccountcontrol", "66048"},
                    {"lastlogon", "132673011142753043"},
                    {"lastlogontimestamp", "132670318095676525"},
                    {"homedirectory", @"\\win10\testdir"},
                    {"mail", "test@testdomain.com"},
                    {
                        "serviceprincipalname", new[]
                        {
                            "MSSQLSVC/win10"
                        }
                    },
                    {"admincount", "1"},
                    {
                        "sidhistory", new[]
                        {
                            Utils.B64ToBytes("AQUAAAAAAAUVAAAAIE+Qun9GhKV2SBaQUQQAAA==")
                        }
                    },
                    {"pwdlastset", "132131667346106691"}
                }, "S-1-5-21-3130019616-2776909439-2417379446-1101","");

            var processor = new LdapPropertyProcessor(new MockLdapUtils());
            var test = await processor.ReadUserProperties(mock, "testlab.local");
            var props = test.Props;
            var keys = props.Keys;

            //Random Stuff
            Assert.Contains("description", keys);
            Assert.Equal("Test", props["description"] as string);
            Assert.Contains("admincount", keys);
            Assert.True((bool)props["admincount"]);
            Assert.Contains("lastlogon", keys);
            Assert.Equal(1622827514, (long)props["lastlogon"]);
            Assert.Contains("lastlogontimestamp", keys);
            Assert.Equal(1622558209, (long)props["lastlogontimestamp"]);
            Assert.Contains("pwdlastset", keys);
            Assert.Equal(1568693134, (long)props["pwdlastset"]);
            Assert.Contains("homedirectory", keys);
            Assert.Equal(@"\\win10\testdir", props["homedirectory"] as string);
            Assert.Contains("email", keys);
            Assert.Equal("test@testdomain.com", props["email"] as string);

            //UAC stuff
            Assert.Contains("sensitive", keys);
            Assert.False((bool)props["sensitive"]);
            Assert.Contains("dontreqpreauth", keys);
            Assert.False((bool)props["dontreqpreauth"]);
            Assert.Contains("passwordnotreqd", keys);
            Assert.False((bool)props["passwordnotreqd"]);
            Assert.Contains("unconstraineddelegation", keys);
            Assert.False((bool)props["unconstraineddelegation"]);
            Assert.Contains("enabled", keys);
            Assert.True((bool)props["enabled"]);
            Assert.Contains("trustedtoauth", keys);
            Assert.False((bool)props["trustedtoauth"]);

            //SPN
            Assert.Contains("hasspn", keys);
            Assert.True((bool)props["hasspn"]);
            Assert.Contains("serviceprincipalnames", keys);
            Assert.Contains("MSSQLSVC/win10", props["serviceprincipalnames"] as string[]);

            //SidHistory
            Assert.Contains("sidhistory", keys);
            var sh = props["sidhistory"] as string[];
            Assert.Single(sh);
            Assert.Contains("S-1-5-21-3130019616-2776909439-2417379446-1105", sh);
            Assert.Single(test.SidHistory);
            Assert.Contains(new TypedPrincipal
            {
                ObjectIdentifier = "S-1-5-21-3130019616-2776909439-2417379446-1105",
                ObjectType = Label.User
            }, test.SidHistory);
        }

        [Fact]
        public async Task LDAPPropertyProcessor_ReadUserProperties_TestBadPaths()
        {
            var mock = new MockDirectoryObject("CN\u003ddfm,CN\u003dUsers,DC\u003dtestlab,DC\u003dlocal",
                new Dictionary<string, object>
                {
                    {"description", "Test"},
                    {"useraccountcontrol", "abc"},
                    {"lastlogon", "132673011142753043"},
                    {"lastlogontimestamp", "132670318095676525"},
                    {"homedirectory", @"\\win10\testdir"},
                    {
                        "serviceprincipalname", new[]
                        {
                            "MSSQLSVC/win10"
                        }
                    },
                    {"admincount", "c"},
                    {
                        "sidhistory", new[]
                        {
                            Array.Empty<byte>()
                        }
                    },
                    {"pwdlastset", "132131667346106691"}
                }, "S-1-5-21-3130019616-2776909439-2417379446-1101","");

            var processor = new LdapPropertyProcessor(new MockLdapUtils());
            var test = await processor.ReadUserProperties(mock, "testlab.local");
            var props = test.Props;
            var keys = props.Keys;

            Assert.Contains("sidhistory", keys);
            Assert.Empty(props["sidhistory"] as string[]);
            Assert.Contains("admincount", keys);
            Assert.False((bool)props["admincount"]);
            Assert.Contains("sensitive", keys);
            Assert.Contains("dontreqpreauth", keys);
            Assert.Contains("passwordnotreqd", keys);
            Assert.Contains("unconstraineddelegation", keys);
            Assert.Contains("pwdneverexpires", keys);
            Assert.Contains("enabled", keys);
            Assert.Contains("trustedtoauth", keys);
            Assert.False((bool)props["trustedtoauth"]);
            Assert.False((bool)props["sensitive"]);
            Assert.False((bool)props["dontreqpreauth"]);
            Assert.False((bool)props["passwordnotreqd"]);
            Assert.False((bool)props["unconstraineddelegation"]);
            Assert.False((bool)props["pwdneverexpires"]);
            Assert.True((bool)props["enabled"]);
        }

        [WindowsOnlyFact]
        public async Task LDAPPropertyProcessor_ReadComputerProperties_HappyPath()
        {
            //TODO: Add coverage for allowedtoact
            var mock = new MockDirectoryObject("CN\u003dWIN10,OU\u003dTestOU,DC\u003dtestlab,DC\u003dlocal",
                new Dictionary<string, object>
                {
                    {"description", "Test"},
                    {"useraccountcontrol", 0x1001000.ToString()},
                    {"lastlogon", "132673011142753043"},
                    {"lastlogontimestamp", "132670318095676525"},
                    {"operatingsystem", "Windows 10 Enterprise"},
                    {"operatingsystemservicepack", "1607"},
                    {"mail", "test@testdomain.com"},
                    {"admincount", "c"},
                    {
                        "sidhistory", new[]
                        {
                            Utils.B64ToBytes("AQUAAAAAAAUVAAAAIE+Qun9GhKV2SBaQUQQAAA==")
                        }
                    },
                    {
                        "msds-allowedtodelegateto", new[]
                        {
                            "ldap/PRIMARY.testlab.local/testlab.local",
                            "ldap/PRIMARY.testlab.local",
                            "ldap/PRIMARY"
                        }
                    },
                    {"pwdlastset", "132131667346106691"},
                    {
                        "serviceprincipalname", new[]
                        {
                            "WSMAN/WIN10",
                            "WSMAN/WIN10.testlab.local",
                            "RestrictedKrbHost/WIN10",
                            "HOST/WIN10",
                            "RestrictedKrbHost/WIN10.testlab.local",
                            "HOST/WIN10.testlab.local"
                        }
                    }
                }, "S-1-5-21-3130019616-2776909439-2417379446-1101","");

            var processor = new LdapPropertyProcessor(new MockLdapUtils());
            var test = await processor.ReadComputerProperties(mock, "testlab.local");
            var props = test.Props;
            var keys = props.Keys;

            //UAC
            Assert.Contains("enabled", keys);
            Assert.Contains("unconstraineddelegation", keys);
            Assert.Contains("trustedtoauth", keys);
            Assert.Contains("isdc", keys);
            Assert.Contains("lastlogon", keys);
            Assert.Contains("lastlogontimestamp", keys);
            Assert.Contains("pwdlastset", keys);
            Assert.True((bool)props["enabled"]);
            Assert.False((bool)props["unconstraineddelegation"]);
            Assert.True((bool)props["trustedtoauth"]);
            Assert.False((bool)props["isdc"]);

            Assert.Contains("lastlogon", keys);
            Assert.Equal(1622827514, (long)props["lastlogon"]);
            Assert.Contains("lastlogontimestamp", keys);
            Assert.Equal(1622558209, (long)props["lastlogontimestamp"]);
            Assert.Contains("pwdlastset", keys);
            Assert.Equal(1568693134, (long)props["pwdlastset"]);

            //AllowedToDelegate
            Assert.Single(test.AllowedToDelegate);
            Assert.Contains(new TypedPrincipal
            {
                ObjectIdentifier = "S-1-5-21-3130019616-2776909439-2417379446-1001",
                ObjectType = Label.Computer
            }, test.AllowedToDelegate);

            //Other Stuff
            Assert.Contains("serviceprincipalnames", keys);
            Assert.Equal(6, (props["serviceprincipalnames"] as string[]).Length);
            Assert.Contains("operatingsystem", keys);
            Assert.Equal("Windows 10 Enterprise 1607", props["operatingsystem"] as string);
            Assert.Contains("description", keys);
            Assert.Equal("Test", props["description"] as string);
            Assert.Contains("email", keys);
            Assert.Equal("test@testdomain.com", props["email"] as string);

            //SidHistory
            Assert.Contains("sidhistory", keys);
            var sh = props["sidhistory"] as string[];
            Assert.Single(sh);
            Assert.Contains("S-1-5-21-3130019616-2776909439-2417379446-1105", sh);
            Assert.Single(test.SidHistory);
            Assert.Contains(new TypedPrincipal
            {
                ObjectIdentifier = "S-1-5-21-3130019616-2776909439-2417379446-1105",
                ObjectType = Label.User
            }, test.SidHistory);
        }

        [Fact]
        public async Task LDAPPropertyProcessor_ReadComputerProperties_TestBadPaths()
        {
            var mock = new MockDirectoryObject("CN\u003dWIN10,OU\u003dTestOU,DC\u003dtestlab,DC\u003dlocal",
                new Dictionary<string, object>
                {
                    {"description", "Test"},
                    {"useraccountcontrol", "abc"},
                    {"lastlogon", "132673011142753043"},
                    {"lastlogontimestamp", "132670318095676525"},
                    {"operatingsystem", "Windows 10 Enterprise"},
                    {"admincount", "c"},
                    {
                        "sidhistory", new[]
                        {
                            Array.Empty<byte>()
                        }
                    },
                    {
                        "msds-allowedToDelegateTo", new[]
                        {
                            "ldap/PRIMARY.testlab.local/testlab.local",
                            "ldap/PRIMARY.testlab.local",
                            "ldap/PRIMARY"
                        }
                    },
                    {"pwdlastset", "132131667346106691"},
                    {
                        "serviceprincipalname", new[]
                        {
                            "WSMAN/WIN10",
                            "WSMAN/WIN10.testlab.local",
                            "RestrictedKrbHost/WIN10",
                            "HOST/WIN10",
                            "RestrictedKrbHost/WIN10.testlab.local",
                            "HOST/WIN10.testlab.local"
                        }
                    }
                }, "S-1-5-21-3130019616-2776909439-2417379446-1101", "");

            var processor = new LdapPropertyProcessor(new MockLdapUtils());
            var test = await processor.ReadComputerProperties(mock, "testlab.local");
            var props = test.Props;
            var keys = props.Keys;

            Assert.Contains("unconstraineddelegation", keys);
            Assert.Contains("enabled", keys);
            Assert.Contains("trustedtoauth", keys);
            Assert.False((bool)props["unconstraineddelegation"]);
            Assert.True((bool)props["enabled"]);
            Assert.False((bool)props["trustedtoauth"]);
            Assert.Contains("sidhistory", keys);
            Assert.Empty(props["sidhistory"] as string[]);
        }


        [Fact]
        public async Task LDAPPropertyProcessor_ReadComputerProperties_TestDumpSMSAPassword()
        {
            var mock = new MockDirectoryObject("CN\u003dWIN10,OU\u003dTestOU,DC\u003dtestlab,DC\u003dlocal",
                new Dictionary<string, object>
                {
                    {"description", "Test"},
                    {"useraccountcontrol", 0x1001000.ToString()},
                    {"lastlogon", "132673011142753043"},
                    {"lastlogontimestamp", "132670318095676525"},
                    {"operatingsystem", "Windows 10 Enterprise"},
                    {"operatingsystemservicepack", "1607"},
                    {"admincount", "c"},
                    {
                        "sidhistory", new[]
                        {
                            Utils.B64ToBytes("AQUAAAAAAAUVAAAAIE+Qun9GhKV2SBaQUQQAAA==")
                        }
                    },
                    {
                        "msds-allowedtodelegateto", new[]
                        {
                            "ldap/PRIMARY.testlab.local/testlab.local",
                            "ldap/PRIMARY.testlab.local",
                            "ldap/PRIMARY"
                        }
                    },
                    {"pwdlastset", "132131667346106691"},
                    {
                        "serviceprincipalname", new[]
                        {
                            "WSMAN/WIN10",
                            "WSMAN/WIN10.testlab.local",
                            "RestrictedKrbHost/WIN10",
                            "HOST/WIN10",
                            "RestrictedKrbHost/WIN10.testlab.local",
                            "HOST/WIN10.testlab.local"
                        }
                    },
                    {
                        "msds-hostserviceaccount", new[]
                        {
                            "CN=dfm,CN=Users,DC=testlab,DC=local",
                            "CN=krbtgt,CN=Users,DC=testlab,DC=local"
                        }
                    }
                }, "S-1-5-21-3130019616-2776909439-2417379446-1101", "");

            var processor = new LdapPropertyProcessor(new MockLdapUtils());
            var test = await processor.ReadComputerProperties(mock, "testlab.local");

            var expected = new TypedPrincipal[]
            {
                new()
                {
                    ObjectIdentifier = "S-1-5-21-3130019616-2776909439-2417379446-1105",
                    ObjectType = Label.User
                },
                new()
                {
                    ObjectIdentifier = "S-1-5-21-3130019616-2776909439-2417379446-502",
                    ObjectType = Label.User
                }
            };

            var testDumpSMSAPassword = test.DumpSMSAPassword;
            Assert.Equal(2, testDumpSMSAPassword.Length);
            Assert.Equal(expected, testDumpSMSAPassword);

        }

        [Fact]
        public void LDAPPropertyProcessor_ReadRootCAProperties()
        {
            var mock = new MockDirectoryObject(
                "CN\u003dDUMPSTER-DC01-CA,CN\u003dCERTIFICATION AUTHORITIES,CN\u003dPUBLIC KEY SERVICES,CN\u003dSERVICES,CN\u003dCONFIGURATION,DC\u003dDUMPSTER,DC\u003dFIRE",
                new Dictionary<string, object>
                {
                    {"description", null},
                    {"domain", "DUMPSTER.FIRE"},
                    {"name", "DUMPSTER-DC01-CA@DUMPSTER.FIRE"},
                    {"domainsid", "S-1-5-21-2697957641-2271029196-387917394"},
                    {"whencreated", 1683986131},
                }, "","2F9F3630-F46A-49BF-B186-6629994EBCF9");

            var test = LdapPropertyProcessor.ReadRootCAProperties(mock);
            var keys = test.Keys;

            //These are not common properties
            Assert.DoesNotContain("domain", keys);
            Assert.DoesNotContain("name", keys);
            Assert.DoesNotContain("domainsid", keys);

            Assert.Contains("whencreated", keys);
        }

        [Fact]
        public void LDAPPropertyProcessor_ReadAIACAProperties() {
            var ecdsa = ECDsa.Create();
            var req = new CertificateRequest("cn=foobar", ecdsa, HashAlgorithmName.SHA256);
            var cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(5));

            var bytes = cert.Export(X509ContentType.Cert, "abc");
            var mock = new MockDirectoryObject(
                "CN\u003dDUMPSTER-DC01-CA,CN\u003dAIA,CN\u003dPUBLIC KEY SERVICES,CN\u003dSERVICES,CN\u003dCONFIGURATION,DC\u003dDUMPSTER,DC\u003dFIRE",
                new Dictionary<string, object>
                {
                    {"description", null},
                    {"domain", "DUMPSTER.FIRE"},
                    {"name", "DUMPSTER-DC01-CA@DUMPSTER.FIRE"},
                    {"domainsid", "S-1-5-21-2697957641-2271029196-387917394"},
                    {"whencreated", 1683986131},
                    {"hascrosscertificatepair", true},
                    {LDAPProperties.CACertificate, bytes}
                }, "","2F9F3630-F46A-49BF-B186-6629994EBCF9");

            var test = LdapPropertyProcessor.ReadAIACAProperties(mock);
            var keys = test.Keys;

            //These are not common properties
            Assert.DoesNotContain("domain", keys);
            Assert.DoesNotContain("name", keys);
            Assert.DoesNotContain("domainsid", keys);

            Assert.Contains("whencreated", keys);
            Assert.Contains("crosscertificatepair", keys);
            Assert.Contains("certthumbprint", keys);
            Assert.Contains("certname", keys);
            Assert.Contains("certchain", keys);
            Assert.Contains("hasbasicconstraints", keys);
            Assert.Contains("basicconstraintpathlength", keys);
        }

        [Fact]
        public void LDAPPropertyProcessor_ReadNTAuthStoreProperties()
        {
            var mock = new MockDirectoryObject("CN\u003dNTAUTHCERTIFICATES,CN\u003dPUBLIC KEY SERVICES,CN\u003dSERVICES,CN\u003dCONFIGURATION,DC\u003dDUMPSTER,DC\u003dFIRE",
                new Dictionary<string, object>
                {
                    {"description", null},
                    {"domain", "DUMPSTER.FIRE"},
                    {"name", "NTAUTHCERTIFICATES@DUMPSTER.FIRE"},
                    {"domainsid", "S-1-5-21-2697957641-2271029196-387917394"},
                    {"whencreated", 1683986131},
                }, "","2F9F3630-F46A-49BF-B186-6629994EBCF9");

            var test = LdapPropertyProcessor.ReadNTAuthStoreProperties(mock);
            var keys = test.Keys;

            //These are not common properties
            Assert.DoesNotContain("domain", keys);
            Assert.DoesNotContain("name", keys);
            Assert.DoesNotContain("domainsid", keys);

            Assert.Contains("whencreated", keys);
        }

        [Fact]
        public void LDAPPropertyProcessor_ReadCertTemplateProperties()
        {
            var mock = new MockDirectoryObject("CN\u003dWORKSTATION,CN\u003dCERTIFICATE TEMPLATES,CN\u003dPUBLIC KEY SERVICES,CN\u003dSERVICES,CN\u003dCONFIGURATION,DC\u003dEXTERNAL,DC\u003dLOCAL",
                new Dictionary<string, object>
                {
                    {"domain", "EXTERNAL.LOCAL"},
                    {"name", "WORKSTATION@EXTERNAL.LOCAL"},
                    {"domainsid", "S-1-5-21-3702535222-3822678775-2090119576"},
                    {"description", null},
                    {"whencreated", 1683986183},
                    {"validityperiod", 31536000},
                    {"renewalperiod", 3628800},
                    {LDAPProperties.TemplateSchemaVersion, 2},
                    {"displayname", "Workstation Authentication"},
                    {"oid", "1.3.6.1.4.1.311.21.8.4571196.1884641.3293620.10686285.12068043.134.1.30"},
                    {LDAPProperties.PKIEnrollmentFlag, 32},
                    {"requiresmanagerapproval", false},
                    {LDAPProperties.PKINameFlag, 0x8000000},
                    {"ekus", new[]
                        {"1.3.6.1.5.5.7.3.2"}
                    },
                    {LDAPProperties.CertificateApplicationPolicy, new[]
                        {"1.3.6.1.5.5.7.3.2"}
                    },
                    {LDAPProperties.CertificatePolicy, new[]
                        {"1.3.6.1.5.5.7.3.2"}
                    },
                    {LDAPProperties.NumSignaturesRequired, 1},
                    {"applicationpolicies", new[]
                        {  "1.3.6.1.4.1.311.20.2.1"}
                    },
                    {"issuancepolicies", new[]
                        {"1.3.6.1.4.1.311.21.8.4571196.1884641.3293620.10686285.12068043.134.1.400",
                            "1.3.6.1.4.1.311.21.8.4571196.1884641.3293620.10686285.12068043.134.1.402"}
                    },
                    {LDAPProperties.PKIPrivateKeyFlag, 256},
                }, "","2F9F3630-F46A-49BF-B186-6629994EBCF9");

            var test = LdapPropertyProcessor.ReadCertTemplateProperties(mock);
            var keys = test.Keys;

            //These are not common properties
            Assert.DoesNotContain("domain", keys);
            Assert.DoesNotContain("name", keys);
            Assert.DoesNotContain("domainsid", keys);

            Assert.Contains("whencreated", keys);
            Assert.Contains("validityperiod", keys);
            Assert.Contains("renewalperiod", keys);
            Assert.Contains("schemaversion", keys);
            Assert.Contains("displayname", keys);
            Assert.Contains("oid", keys);
            Assert.Contains("enrollmentflag", keys);
            Assert.Contains("requiresmanagerapproval", keys);
            Assert.Contains("certificatenameflag", keys);
            Assert.Contains("enrolleesuppliessubject", keys);
            Assert.Contains("subjectaltrequireupn", keys);
            Assert.Contains("subjectaltrequiredns", keys);
            Assert.Contains("subjectaltrequiredomaindns", keys);
            Assert.Contains("subjectaltrequireemail", keys);
            Assert.Contains("subjectaltrequirespn", keys);
            Assert.Contains("subjectrequireemail", keys);
            Assert.Contains("ekus", keys);
            Assert.Contains("certificateapplicationpolicy", keys);
            var hasPolicy = test.TryGetValue("certificatepolicy", out var policies);
            Assert.True(hasPolicy);
            if (policies is string[] e)
            {
                Assert.Contains("1.3.6.1.5.5.7.3.2", e);
            }
            Assert.Contains("authorizedsignatures", keys);
            Assert.Contains("applicationpolicies", keys);
            Assert.Contains("issuancepolicies", keys);

        }
        
        [Fact]
        public async Task LDAPPropertyProcessor_ReadIssuancePolicyProperties()
        {
            var mock = new MockDirectoryObject("CN\u003d6250993.11BB1AB25A8A65E9FCDF709FCDD5FBC6,CN\u003dOID,CN\u003dPUBLIC KEY SERVICES,CN\u003dSERVICES,CN\u003dCONFIGURATION,DC\u003dESC10,DC\u003dLOCAL",
                new Dictionary<string, object>
                {
                    {LDAPProperties.Description, null},
                    {LDAPProperties.WhenCreated, 1712567279},
                    {LDAPProperties.DisplayName, "KeyAdminsOID"},
                    {LDAPProperties.CertTemplateOID, "1.3.6.1.4.1.311.21.8.4571196.1884641.3293620.10686285.12068043.134.1.30"},
                    {LDAPProperties.OIDGroupLink, "CN=ENTERPRISE KEY ADMINS,CN=USERS,DC=ESC10,DC=LOCAL"}
                    ,
                }, "","1E5311A8-E949-4E02-8E08-234ED63200DE");
        
            var mockLDAPUtils = new MockLdapUtils();
            var ldapPropertyProcessor = new LdapPropertyProcessor(mockLDAPUtils);
        
        
            var test = await ldapPropertyProcessor.ReadIssuancePolicyProperties(mock);
            var keys = test.Props.Keys;
        
            //These are not common properties
            Assert.DoesNotContain("domain", keys);
            Assert.DoesNotContain("name", keys);
            Assert.DoesNotContain("domainsid", keys);
        
            Assert.Contains("whencreated", keys);
            Assert.Contains("displayname", keys);
            Assert.Contains("certtemplateoid", keys);
            Assert.Contains("oidgrouplink", keys);
        }
        
        [Fact]
        public async Task LDAPPropertyProcessor_ReadIssuancePolicyProperties_NoOIDGroupLink()
        {
            var mock = new MockDirectoryObject("CN\u003d6250993.11BB1AB25A8A65E9FCDF709FCDD5FBC6,CN\u003dOID,CN\u003dPUBLIC KEY SERVICES,CN\u003dSERVICES,CN\u003dCONFIGURATION,DC\u003dESC10,DC\u003dLOCAL",
                new Dictionary<string, object>
                {
                    {LDAPProperties.Description, null},
                    {LDAPProperties.WhenCreated, 1712567279},
                    {LDAPProperties.DisplayName, "KeyAdminsOID"},
                    {LDAPProperties.CertTemplateOID, "1.3.6.1.4.1.311.21.8.4571196.1884641.3293620.10686285.12068043.134.1.30"},
                    {LDAPProperties.OIDGroupLink, null}
                    ,
                }, "","1E5311A8-E949-4E02-8E08-234ED63200DE");
        
            var mockLDAPUtils = new MockLdapUtils();
            var ldapPropertyProcessor = new LdapPropertyProcessor(mockLDAPUtils);
            
            var test = await ldapPropertyProcessor.ReadIssuancePolicyProperties(mock);
            var keys = test.Props.Keys;
        
            //These are not common properties
            Assert.DoesNotContain("domain", keys);
            Assert.DoesNotContain("name", keys);
            Assert.DoesNotContain("domainsid", keys);
            Assert.DoesNotContain("oidgrouplink", keys);
        
            //Assert.Contains("description", keys);
            Assert.Contains("whencreated", keys);
            Assert.Contains("displayname", keys);
            Assert.Contains("certtemplateoid", keys);
        }

        [Fact]
        public void LDAPPropertyProcessor_ParseAllProperties()
        {
            var mock = new MockDirectoryObject("CN\u003dNTAUTHCERTIFICATES,CN\u003dPUBLIC KEY SERVICES,CN\u003dSERVICES,CN\u003dCONFIGURATION,DC\u003dDUMPSTER,DC\u003dFIRE",
                new Dictionary<string, object>
                {
                    {"description", null},
                    {"domain", "DUMPSTER.FIRE"},
                    {"name", "NTAUTHCERTIFICATES@DUMPSTER.FIRE"},
                    {"domainsid", "S-1-5-21-2697957641-2271029196-387917394"},
                    {"whencreated", 1683986131},
                    {"dsasignature", "jkr"}
                }, "", "2F9F3630-F46A-49BF-B186-6629994EBCF9");

            var processor = new LdapPropertyProcessor(new MockLdapUtils());
            var props = processor.ParseAllProperties(mock);
            var keys = props.Keys;

            //These are reserved properties and so they should be filtered out
            Assert.DoesNotContain("description", keys);
            Assert.DoesNotContain("whencreated", keys);
            Assert.DoesNotContain("name", keys);
            Assert.DoesNotContain("dsasignature", keys);

            Assert.Contains("domainsid", keys);
            Assert.Contains("domain", keys);
        }

        [Fact]
        public void LDAPPropertyProcessor_ParseAllProperties_NoProperties()
        {
            var mock = new MockDirectoryObject("CN\u003dNTAUTHCERTIFICATES,CN\u003dPUBLIC KEY SERVICES,CN\u003dSERVICES,CN\u003dCONFIGURATION,DC\u003dDUMPSTER,DC\u003dFIRE",
                new Dictionary<string, object>
                    { }, "","2F9F3630-F46A-49BF-B186-6629994EBCF9");

            var processor = new LdapPropertyProcessor(new MockLdapUtils());
            var props = processor.ParseAllProperties(mock);
            var keys = props.Keys;

            Assert.Empty(keys);

        }

        [Fact]
        public void LDAPPropertyProcessor_ParseAllProperties_CollectionCountOne_NullString()
        {
            var mock = new MockDirectoryObject("CN\u003dNTAUTHCERTIFICATES,CN\u003dPUBLIC KEY SERVICES,CN\u003dSERVICES,CN\u003dCONFIGURATION,DC\u003dDUMPSTER,DC\u003dFIRE",
                new Dictionary<string, object>
                    {{"domainsid", null} }, "","2F9F3630-F46A-49BF-B186-6629994EBCF9");

            var processor = new LdapPropertyProcessor(new MockLdapUtils());
            var props = processor.ParseAllProperties(mock);
            var keys = props.Keys;

            Assert.Empty(keys);
        }

        [Fact]
        public void LDAPPropertyProcessor_ParseAllProperties_CollectionCountOne_BadPasswordTime()
        {
            var mock = new MockDirectoryObject("CN\u003dNTAUTHCERTIFICATES,CN\u003dPUBLIC KEY SERVICES,CN\u003dSERVICES,CN\u003dCONFIGURATION,DC\u003dDUMPSTER,DC\u003dFIRE",
                new Dictionary<string, object>
                    {{"badpasswordtime", "130435290000000000"} }, "","2F9F3630-F46A-49BF-B186-6629994EBCF9");

            var processor = new LdapPropertyProcessor(new MockLdapUtils());
            var props = processor.ParseAllProperties(mock);
            var keys = props.Keys;

            Assert.Contains("badpasswordtime", keys);
            Assert.Single(keys);
        }

        [Fact]
        public void LDAPPropertyProcessor_ParseAllProperties_CollectionCountOne_NotBadPasswordTime()
        {
            var mock = new MockDirectoryObject("CN\u003dNTAUTHCERTIFICATES,CN\u003dPUBLIC KEY SERVICES,CN\u003dSERVICES,CN\u003dCONFIGURATION,DC\u003dDUMPSTER,DC\u003dFIRE",
                new Dictionary<string, object>
                    {{"domainsid", "S-1-5-21-2697957641-2271029196-387917394"}}, "","2F9F3630-F46A-49BF-B186-6629994EBCF9");

            var processor = new LdapPropertyProcessor(new MockLdapUtils());
            var props = processor.ParseAllProperties(mock);
            var keys = props.Keys;

            Assert.Contains("domainsid", keys);
            Assert.Single(keys);
        }

        [Fact]
        public void LDAPPropertyProcessor_ParseAllProperties_CollectionCountOne_ControlCharactersAreEncoded() {
            var mock = new MockDirectoryObject("CN\u003dNTAUTHCERTIFICATES,CN\u003dPUBLIC KEY SERVICES,CN\u003dSERVICES,CN\u003dCONFIGURATION,DC\u003dDUMPSTER,DC\u003dFIRE",
                new Dictionary<string, object>
                    {{"usercertificate", "\u0000"}}, "", "2F9F3630-F46A-49BF-B186-6629994EBCF9");

            var processor = new LdapPropertyProcessor(new MockLdapUtils());
            var props = processor.ParseAllProperties(mock);
            var keys = props.Keys;

            Assert.Contains("usercertificate", keys);
            Assert.Single(keys);
            var hasCert = props.TryGetValue("usercertificate", out var usercert);
            Assert.True(hasCert);
            Assert.Equal("\u0000", System.Text.Encoding.UTF8.GetString(usercert as byte[]));
        }

        [WindowsOnlyFact]
        public void LDAPPropertyProcessor_ParseAllProperties_CollectionCountOne_SID() {
            var mock = new MockDirectoryObject("CN\u003dNTAUTHCERTIFICATES,CN\u003dPUBLIC KEY SERVICES,CN\u003dSERVICES,CN\u003dCONFIGURATION,DC\u003dDUMPSTER,DC\u003dFIRE",
                new Dictionary<string, object>
                    {{"ms-ds-creatorsid", "S-1-5-21-2697957641-2271029196-387917394"}}, "", "2F9F3630-F46A-49BF-B186-6629994EBCF9");

            var processor = new LdapPropertyProcessor(new MockLdapUtils());
            var props = processor.ParseAllProperties(mock);
            var keys = props.Keys;

            Assert.Contains("ms-ds-creatorsid", keys);
            Assert.Single(keys);
            var hasSID = props.TryGetValue("ms-ds-creatorsid", out var creatorSID);
            Assert.True(hasSID);
            Assert.Equal("S-1-5-21-2697957641-2271029196-387917394", props["ms-ds-creatorsid"]);
        }

        [Fact]
        public void LDAPPropertyProcessor_ParseAllProperties_CollectionCountOne_GUID() {
            var guid = Guid.NewGuid().ToString();
            Console.WriteLine(guid);
            var mock = new MockDirectoryObject("CN\u003dNTAUTHCERTIFICATES,CN\u003dPUBLIC KEY SERVICES,CN\u003dSERVICES,CN\u003dCONFIGURATION,DC\u003dDUMPSTER,DC\u003dFIRE",
                new Dictionary<string, object>
                    {{"guid", guid}}, "", "2F9F3630-F46A-49BF-B186-6629994EBCF9");

            var processor = new LdapPropertyProcessor(new MockLdapUtils());
            var props = processor.ParseAllProperties(mock);
            var keys = props.Keys;

            Assert.Contains("guid", keys);
            Assert.Single(keys);
            var hasGuid = props.TryGetValue("guid", out var guid2);
            Assert.True(hasGuid);
            Console.WriteLine(guid);
            Assert.Equal(guid, guid2);
        }
    }
}
