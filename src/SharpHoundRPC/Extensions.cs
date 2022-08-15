using System;
using System.Security.Principal;
using FluentResults;

namespace SharpHoundRPC
{
    public static class Extensions
    {
        public static bool IsError(this NtStatus status)
        {
            if (status != NtStatus.StatusSuccess && status != NtStatus.StatusMoreEntries &&
                status != NtStatus.StatusSomeMapped && status != NtStatus.StatusNoMoreEntries)
                return true;

            return false;
        }

        public static Result<T> ResultValue<T>(this Result result, string failureMessage, T value)
        {
            if (result.IsSuccess)
            {
                return Result.Ok(value);
            }

            return Result.Fail(failureMessage);
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

        public static byte[] GetBytes(this SecurityIdentifier identifier)
        {
            var bytes = new byte[identifier.BinaryLength];
            identifier.GetBinaryForm(bytes, 0);
            return bytes;
        } 
    }
}