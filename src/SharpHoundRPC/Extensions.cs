namespace SharpHoundRPC
{
    public static class Extensions
    {
        public static void CheckError(this NtStatus status, string apiCall)
        {
            if (status != NtStatus.StatusSuccess && status != NtStatus.StatusMoreEntries &&
                status != NtStatus.StatusSomeMapped && status != NtStatus.StatusNoMoreEntries)
                throw new RPCException(apiCall, status);
        }
    }
}