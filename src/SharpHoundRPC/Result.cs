namespace SharpHoundRPC
{
    public class Result<T>
    {
        private NtStatus Status { get; set; } = NtStatus.StatusSuccess;
        public T Value { get; private set; }

        public bool IsFailed => Status.IsError();

        public static Result<T> Fail(NtStatus status)
        {
            var result = new Result<T>
            {
                Status = status
            };
            return result;
        }

        public static Result<T> Ok(T value)
        {
            var result = new Result<T>
            {
                Value = value
            };
            return result;
        }

        public static implicit operator Result<T>(T input)
        {
            return Ok(input);
        }

        public static implicit operator Result<T>(NtStatus status)
        {
            return Fail(status);
        }
    }
}