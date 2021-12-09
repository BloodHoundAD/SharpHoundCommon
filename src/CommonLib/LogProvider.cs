using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace SharpHoundCommonLib
{
    public class LogProvider : ILoggerProvider
    {
        private readonly ConcurrentDictionary<string, PassThroughLogger> _loggers = new();

        public void Dispose()
        {
            _loggers.Clear();
        }

        public ILogger CreateLogger(string categoryName)
        {
            return _loggers.GetOrAdd(categoryName, name => new PassThroughLogger(name));
        }
    }
}