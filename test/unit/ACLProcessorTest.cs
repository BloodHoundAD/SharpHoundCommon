using System;
using System.Linq;
using CommonLibTest.Facades;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.Processors;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest
{
    public class ACLProcessorTest : IDisposable
    {
        private readonly ITestOutputHelper _testOutputHelper;
        private ACLProcessor _baseProcessor;
        private readonly string _testDomainName;
        private const string ProtectedUserNTSecurityDescriptor =
            "AQAEnIgEAAAAAAAAAAAAABQAAAAEAHQEGAAAAAUAPAAQAAAAAwAAAABCFkzAINARp2gAqgBuBSkUzChINxS8RZsHrW8BXl8oAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAABCFkzAINARp2gAqgBuBSm6epa/5g3QEaKFAKoAMEniAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAABAgIF+ledARkCAAwE/C1M8UzChINxS8RZsHrW8BXl8oAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAABAgIF+ledARkCAAwE/C1M+6epa/5g3QEaKFAKoAMEniAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAEDCCrypedARkCAAwE/C1M8UzChINxS8RZsHrW8BXl8oAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAEDCCrypedARkCAAwE/C1M+6epa/5g3QEaKFAKoAMEniAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAEIvulmiedARkCAAwE/C088UzChINxS8RZsHrW8BXl8oAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAEIvulmiedARkCAAwE/C08+6epa/5g3QEaKFAKoAMEniAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAPiIcAPhCtIRtCIAoMlo+TkUzChINxS8RZsHrW8BXl8oAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAPiIcAPhCtIRtCIAoMlo+Tm6epa/5g3QEaKFAKoAMEniAQIAAAAAAAUgAAAAKgIAAAUAOAAwAAAAAQAAAH96lr/mDdARooUAqgAwSeIBBQAAAAAABRUAAAAgT5C6f0aEpXZIFpAFAgAABQAsABAAAAABAAAAHbGpRq5gWkC36P+KWNRW0gECAAAAAAAFIAAAADACAAAFACwAMAAAAAEAAAAcmrZtIpTREa69AAD4A2fBAQIAAAAAAAUgAAAAMQIAAAUALAAwAAAAAQAAAGK8BVjJvShEpeKFag9MGF4BAgAAAAAABSAAAAAxAgAABQAsAJQAAgACAAAAFMwoSDcUvEWbB61vAV5fKAECAAAAAAAFIAAAACoCAAAFACwAlAACAAIAAAC6epa/5g3QEaKFAKoAMEniAQIAAAAAAAUgAAAAKgIAAAUAKAAAAQAAAQAAAFMacqsvHtARmBkAqgBAUpsBAQAAAAAAAQAAAAAFACgAAAEAAAEAAABTGnKrLx7QEZgZAKoAQFKbAQEAAAAAAAUKAAAABQIoADABAAABAAAA3kfmkW/ZcEuVV9Y/9PPM2AEBAAAAAAAFCgAAAAAAJAC/AQ4AAQUAAAAAAAUVAAAAIE+Qun9GhKV2SBaQAAIAAAAAJAC/AQ4AAQUAAAAAAAUVAAAAIE+Qun9GhKV2SBaQBwIAAAAAGAC/AQ8AAQIAAAAAAAUgAAAAIAIAAAAAFACUAAIAAQEAAAAAAAULAAAAAAAUAP8BDwABAQAAAAAABRIAAAABBQAAAAAABRUAAAAgT5C6f0aEpXZIFpAAAgAA";
        private const string UnProtectedUserNtSecurityDescriptor =
            "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";
        private const string GMSAProperty =
            "AQAEgEAAAAAAAAAAAAAAABQAAAAEACwAAQAAAAAAJAD/AQ8AAQUAAAAAAAUVAAAAIE+Qun9GhKV2SBaQ9AEAAAECAAAAAAAFIAAAACACAAA\u003d";

        public ACLProcessorTest(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
            _testDomainName = "TESTLAB.LOCAL";
            _baseProcessor = new ACLProcessor(new LDAPUtils());
        }
        
        [Fact]
        public void SanityCheck()
        {
            Assert.True(true);
        }

        [Fact]
        public void ACLProcessor_IsACLProtected_NullNTSD_ReturnsFalse()
        {
            var result = ACLProcessor.IsACLProtected(null);
            Assert.False(result);
        }

        [WindowsOnlyFact]
        public void ACLProcessor_IsACLProtected_ReturnsTrue()
        {
            var bytes = Helpers.B64ToBytes(ProtectedUserNTSecurityDescriptor);
            var result = ACLProcessor.IsACLProtected(bytes);
            Assert.True(result);
        }

        [WindowsOnlyFact]
        public void ACLProcessor_IsACLProtected_ReturnsFalse()
        {
            var bytes = Helpers.B64ToBytes(UnProtectedUserNtSecurityDescriptor);
            var result = ACLProcessor.IsACLProtected(bytes);
            Assert.False(result);
        }

        [Fact]
        public void ACLProcessor_ProcessGMSAReaders_NullNTSD_ReturnsNothing()
        {
            var test = _baseProcessor.ProcessGMSAReaders(null, null);
            Assert.Empty(test);
        }

        [WindowsOnlyFact]
        public void ACLProcess_ProcessGMSAReaders_YieldsCorrectAce()
        {
            var processor = new ACLProcessor(new MockLDAPUtils(), true);
            var bytes = Helpers.B64ToBytes(GMSAProperty);
            var result = processor.ProcessGMSAReaders(bytes, _testDomainName).ToArray();
            Assert.Single(result);
            var test = result.First();
            _testOutputHelper.WriteLine(test.ToString());
            Assert.Equal("ReadGMSAPassword", test.RightName);
            Assert.Equal("S-1-5-21-3130019616-2776909439-2417379446-500", test.PrincipalSID);
            Assert.Equal(Label.User, test.PrincipalType);
        }

        [WindowsOnlyFact]
        public void ACLProcess_ProcessACL_ProcessTestUser_YieldsCorrectAce()
        {
            var processor = new ACLProcessor(new MockLDAPUtils(), true);
            var bytes = Helpers.B64ToBytes(UnProtectedUserNtSecurityDescriptor);
            var expected = new ACE[]
            {
                new()
                {
                    IsInherited = false,
                    PrincipalType = Label.Group,
                    PrincipalSID = "S-1-5-21-3130019616-2776909439-2417379446-512",
                    RightName = EdgeNames.Owns
                },
                new()
                {
                    IsInherited = false,
                    PrincipalType = Label.Group,
                    PrincipalSID = "TESTLAB.LOCAL-S-1-5-32-548",
                    RightName = EdgeNames.GenericAll
                },
                new()
                {
                    IsInherited = false,
                    PrincipalType = Label.Group,
                    PrincipalSID = "S-1-5-21-3130019616-2776909439-2417379446-512",
                    RightName = EdgeNames.GenericAll
                },
                new()
                {
                    IsInherited = true,
                    PrincipalType = Label.Group,
                    PrincipalSID = "S-1-5-21-3130019616-2776909439-2417379446-519",
                    RightName = EdgeNames.GenericAll
                },
                new()
                {
                    IsInherited = true,
                    PrincipalType = Label.Group,
                    PrincipalSID = "TESTLAB.LOCAL-S-1-5-32-544",
                    RightName = EdgeNames.WriteDacl
                },
                new()
                {
                    IsInherited = true,
                    PrincipalType = Label.Group,
                    PrincipalSID = "TESTLAB.LOCAL-S-1-5-32-544",
                    RightName = EdgeNames.WriteOwner
                },
                new()
                {
                    IsInherited = true,
                    PrincipalType = Label.Group,
                    PrincipalSID = "TESTLAB.LOCAL-S-1-5-32-544",
                    RightName = EdgeNames.AllExtendedRights
                },
                new()
                {
                    IsInherited = true,
                    PrincipalType = Label.Group,
                    PrincipalSID = "TESTLAB.LOCAL-S-1-5-32-544",
                    RightName = EdgeNames.GenericWrite
                }
            };
            
            var result = processor.ProcessACL(bytes, _testDomainName, Label.User, false).ToArray();

            for (var i = 0; i < result.Length; i++)
            {
                _testOutputHelper.WriteLine(expected[i].ToString());
                _testOutputHelper.WriteLine(result[i].ToString());
            }
            Assert.Equal(8, result.Length);
            Assert.Equal(expected, result);
        }

        public void Dispose()
        {
        }
    }
}
