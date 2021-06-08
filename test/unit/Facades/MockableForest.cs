using System.DirectoryServices.ActiveDirectory;

namespace CommonLibTest.Facades
{
    public class MockableForest
    {
        public static Forest Construct()
        {
            var forest = FacadeHelpers.GetUninitializedObject<Forest>();
            FacadeHelpers.SetProperty(forest, "_forestDnsName", "PARENT.LOCAL");

            return forest;
        }
    }
}