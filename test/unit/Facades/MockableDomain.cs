using System.Diagnostics.CodeAnalysis;
using System.DirectoryServices.ActiveDirectory;

namespace CommonLibTest.Facades
{
    [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility")]
    public class MockableDomain
    {
        public static Domain Construct(string domainName)
        {
            var domain = FacadeHelpers.GetUninitializedObject<Domain>();
            FacadeHelpers.SetField(domain, "partitionName", domainName);

            return domain;
        }
    }
}