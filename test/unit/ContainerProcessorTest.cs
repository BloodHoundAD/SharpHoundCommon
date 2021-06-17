using System;
using System.Linq;
using CommonLibTest.Facades;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.Processors;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest
{
    public class ContainerProcessorTest : IDisposable
    {
        private readonly ITestOutputHelper _testOutputHelper;
        private readonly string _testGpLinkString;
        
        public ContainerProcessorTest(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
            _testGpLinkString =
                "[LDAP://cn={94DD0260-38B5-497E-8876-10E7A96E80D0},cn=policies,cn=system,DC=testlab,DC=local;0][LDAP://cn={C52F168C-CD05-4487-B405-564934DA8EFF},cn=policies,cn=system,DC=testlab,DC=local;0][LDAP://cn={1E860A30-603A-45C7-A768-26EE74BE6D5D},cn=policies,cn=system,DC=testlab,DC=local;0]";
        }

        [Fact]
        public void ContainerProcessor_ReadContainerGPLinks_IgnoresNull()
        {
            var processor = new ContainerProcessor(new MockLDAPUtils());
            var test = processor.ReadContainerGPLinks(null);
            Assert.Empty(test);
        }

        [Fact]
        public void ContainerProcessor_ReadContainerGPLinks_UnresolvedGPLink_IsIgnored()
        {
            var processor = new ContainerProcessor(new MockLDAPUtils());
            //GPLink that doesn't exist
            const string s = "[LDAP://cn={94DD0260-38B5-497E-8876-ABCDEFG},cn=policies,cn=system,DC=testlab,DC=local;0]";
            var test = processor.ReadContainerGPLinks(s);
            Assert.Empty(test);
        }

        [Fact]
        public void ContainerProcessor_ReadContainerGPLinks_ReturnsCorrectValues()
        {
            var processor = new ContainerProcessor(new MockLDAPUtils());
            var test = processor.ReadContainerGPLinks(_testGpLinkString).ToArray();

            var expected = new GPLink[]
            {
                new()
                {
                    GUID = "B39818AF-6349-401A-AE0A-E4972F5BF6D9",
                    IsEnforced = false
                },
                new()
                {
                    GUID = "ACDD64D3-67B3-401F-A6CC-804B3F7B1533",
                    IsEnforced = false
                },
                new()
                {
                    GUID = "C45E9585-4932-4C03-91A8-1856869D49AF",
                    IsEnforced = false
                }
            };
            
            Assert.Equal(3, test.Length);
            Assert.Equal(expected, test);
        }
        
        public void Dispose()
        {
        }
    }
}