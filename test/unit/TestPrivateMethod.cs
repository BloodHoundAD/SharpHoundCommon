using System;
using System.Linq;
using System.Reflection;

namespace CommonLibTest
{
    //Class taken from https://stackoverflow.com/questions/41462468/net-core-library-how-to-test-private-methods-using-xunit
    public static class TestPrivateMethod
    {
        public static T StaticMethod<T>(Type classType, string methodName, object[] callParams)
        {
            var methodList = classType
                .GetMethods(BindingFlags.NonPublic | BindingFlags.Static);

            if (methodList is null || !methodList.Any()) 
                throw new EntryPointNotFoundException();
        
            var method = methodList.First(x => x.Name == methodName && !x.IsPublic && x.GetParameters().Length == callParams.Length);

            var output = (T)method.Invoke(null, callParams);

            return output;
        }

        public static T InstanceMethod<T>(object instance, string methodName, object[] callParams)
        {
            var classType = instance.GetType();
            var methodList = classType
                .GetMethods(BindingFlags.NonPublic | BindingFlags.Instance);

            if (methodList is null || !methodList.Any()) 
                throw new EntryPointNotFoundException();
        
            var method = methodList.First(x => x.Name == methodName && !x.IsPublic && x.GetParameters().Length == callParams.Length);

            var output = (T)method.Invoke(instance, callParams);

            return output;
        }
    }
}