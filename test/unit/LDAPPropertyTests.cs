using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest
{
    public class LDAPPropertyTests
    {
        private readonly ITestOutputHelper _testOutputHelper;

        public LDAPPropertyTests(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        [Fact]
        public void LDAPPropertyProcessor_ReadDomainProperties_Test()
        {
            
        }
    }
}