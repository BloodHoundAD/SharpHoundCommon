using System.Reflection;
using System.Runtime.Serialization;

namespace CommonLibTest.Facades
{
    public class FacadeHelpers
    {
        const BindingFlags nonPublicInstance = BindingFlags.NonPublic | BindingFlags.Instance;
        const BindingFlags publicInstance = BindingFlags.Public | BindingFlags.Instance;
        
        internal static T GetUninitializedObject<T>()
        {
            return (T) FormatterServices.GetUninitializedObject(typeof(T));
        }
        
        internal static void SetProperty<T1, T2>(T1 obj, string propertyName, T2 propertyValue)
        {
            var set = typeof(T1).GetField(propertyName, nonPublicInstance);
            set.SetValue(obj, propertyValue);
        }
    }
}