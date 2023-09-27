namespace SharpHoundRPC
{
    public class Result<T>
    {
        public bool IsSuccess { get; private set; }
        public NtStatus Status { get; private set; }
        public T Value { get; private set; }
        public string Error { get; private set; }
        public bool IsFailed => !IsSuccess;

        public static Result<T> Ok(T value)
        {
            return new() {IsSuccess = true, Value = value};
        }

        public static Result<T> Fail(NtStatus status)
        {
            return new() {Status = status};
        }

        public static Result<T> Fail(string error)
        {
            return new() {Error = error};
        }

        public string SError
        {
            get
            {
                if (!string.IsNullOrEmpty(Error))
                {
                    return Error;
                }

                return Status.ToString();
            }
        }

        public static implicit operator Result<T>(T input)
        {
            return Ok(input);
        }

        public static implicit operator Result<T>(NtStatus status)
        {
            return Fail(status);
        }

        public static implicit operator Result<T>(string error)
        {
            return Fail(error);
        }
    }
}