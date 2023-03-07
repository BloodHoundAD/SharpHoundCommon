using System.Security.Principal;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using Xunit;

namespace CommonLibTest
{
    public class ExtensionsTest
    {
        [Fact]
        public void TestIsLocalGroupCollectionSet()
        {
            var methods = ResolvedCollectionMethod.All;
            Assert.True(methods.IsLocalGroupCollectionSet());

            methods = ResolvedCollectionMethod.Container;
            Assert.False(methods.IsLocalGroupCollectionSet());

            methods = ResolvedCollectionMethod.Default;
            Assert.True(methods.IsLocalGroupCollectionSet());
        }

        [Fact]
        public void TestIsComputerCollectionSet()
        {
            var methods = ResolvedCollectionMethod.All;
            Assert.True(methods.IsComputerCollectionSet());

            methods = ResolvedCollectionMethod.Container;
            Assert.False(methods.IsComputerCollectionSet());

            methods = ResolvedCollectionMethod.Default;
            Assert.True(methods.IsComputerCollectionSet());
        }

        [WindowsOnlyFact]
        public void TestGetRid()
        {
            var securityIdentifier = new SecurityIdentifier("S-1-5-32-544");
            Assert.Equal(544, securityIdentifier.Rid());

            securityIdentifier = new SecurityIdentifier("S-1-5-21-3130019616-2776909439-2417379446-2106");
            Assert.Equal(2106, securityIdentifier.Rid());
        }
    }
}