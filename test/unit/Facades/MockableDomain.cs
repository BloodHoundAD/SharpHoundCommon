using System.DirectoryServices.ActiveDirectory;

namespace CommonLibTest.Facades
{
    public class MockableDomain
    {
        public static Domain Construct(string domainName)
        {
            var domain = FacadeHelpers.GetUninitializedObject<Domain>();
            FacadeHelpers.SetProperty(domain, "partitionName", domainName);

            return domain;
        }
    }
}