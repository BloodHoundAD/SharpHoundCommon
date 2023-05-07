namespace SharpHoundRPC.NetAPINative
{
    public class NetAPIResult<T>
    {
        public bool IsSuccess { get; private set; }
        public NetAPIEnums.NetAPIStatus Status { get; private set; }
        public T Value { get; private set; }
        public string Error { get; private set; }
        public bool IsFailed => !IsSuccess;

        public static NetAPIResult<T> Ok(T value)
        {
            return new NetAPIResult<T> {IsSuccess = true, Value = value};
        }

        public static NetAPIResult<T> Fail(NetAPIEnums.NetAPIStatus status)
        {
            return new NetAPIResult<T> {Status = status};
        }

        public static NetAPIResult<T> Fail(string error)
        {
            return new NetAPIResult<T> {Error = error};
        }

        public static implicit operator NetAPIResult<T>(T input)
        {
            return Ok(input);
        }

        public static implicit operator NetAPIResult<T>(NetAPIEnums.NetAPIStatus status)
        {
            return Fail(status);
        }

        public static implicit operator NetAPIResult<T>(string error)
        {
            return Fail(error);
        }
    }
}