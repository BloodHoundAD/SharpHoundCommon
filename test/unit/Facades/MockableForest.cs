using System.Diagnostics.CodeAnalysis;
using System.DirectoryServices.ActiveDirectory;

namespace CommonLibTest.Facades
{
    [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility")]
    public class MockableForest
    {
        public static Forest Construct(string forestDnsName)
        {
            var forest = FacadeHelpers.GetUninitializedObject<Forest>();
            FacadeHelpers.SetField(forest, "_forestDnsName", forestDnsName);

            return forest;
        }
    }
}