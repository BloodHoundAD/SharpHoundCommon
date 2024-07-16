using System;
using System.DirectoryServices;
using System.Linq;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;

namespace SharpHoundCommonLib
{
    public static class Extensions
    {
        private static readonly ILogger Log;

        static Extensions()
        {
            Log = Logging.LogProvider.CreateLogger("Extensions");
        }
        
        // internal static async Task<List<T>> ToListAsync<T>(this IAsyncEnumerable<T> items)
        // {
        //     var results = new List<T>();
        //     await foreach (var item in items
        //                        .ConfigureAwait(false))
        //         results.Add(item);
        //     return results;
        // }

        public static string LdapValue(this SecurityIdentifier s)
        {
            var bytes = new byte[s.BinaryLength];
            s.GetBinaryForm(bytes, 0);

            var output = $"\\{BitConverter.ToString(bytes).Replace('-', '\\')}";
            return output;
        }

        public static string LdapValue(this Guid s)
        {
            var bytes = s.ToByteArray();
            var output = $"\\{BitConverter.ToString(bytes).Replace('-', '\\')}";
            return output;
        }
        
        /// <summary>
        ///     Returns true if any computer collection methods are set
        /// </summary>
        /// <param name="methods"></param>
        /// <returns></returns>
        public static bool IsComputerCollectionSet(this CollectionMethod methods) {
            const CollectionMethod test = CollectionMethod.ComputerOnly | CollectionMethod.LoggedOn;
            return (methods & test) != 0;
        }

        /// <summary>
        ///     Returns true if any local group collections are set
        /// </summary>
        /// <param name="methods"></param>
        /// <returns></returns>
        public static bool IsLocalGroupCollectionSet(this CollectionMethod methods)
        {
            return (methods & CollectionMethod.LocalGroups) != 0;
        }

        /// <summary>
        ///     Gets the relative identifier for a SID
        /// </summary>
        /// <param name="securityIdentifier"></param>
        /// <returns></returns>
        public static int Rid(this SecurityIdentifier securityIdentifier)
        {
            var value = securityIdentifier.Value;
            var rid = int.Parse(value.Substring(value.LastIndexOf("-", StringComparison.Ordinal) + 1));
            return rid;
        }
        
        public static IDirectoryObject ToDirectoryObject(this DirectoryEntry entry) {
            return new DirectoryEntryWrapper(entry);
        }
    }
}