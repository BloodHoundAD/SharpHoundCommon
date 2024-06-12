using System;

namespace SharpHoundCommonLib;

public class LdapResult<T>
{
    public T Value { get; set; }
    public string Error { get; set; }
    public bool IsSuccess => Error == null;
    public string QueryInfo { get; set; }
}