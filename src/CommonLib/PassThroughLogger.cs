using System;
using Microsoft.Extensions.Logging;

namespace SharpHoundCommonLib
{
    internal class PassThroughLogger : ILogger
    {
        private readonly string _name;

        public PassThroughLogger(string name)
        {
            _name = name;
        }

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception,
            Func<TState, Exception, string> formatter)
        {
            Logging.Logger.Log(logLevel, eventId, state, exception, formatter);
        }

        public bool IsEnabled(LogLevel logLevel)
        {
            return true;
        }

        public IDisposable BeginScope<TState>(TState state)
        {
            return default;
        }

        private string FormatLog(string message, Exception e)
        {
            return $"[CommonLib {_name}]{message}{(e != null ? $"\n{e}" : "")}";
        }
    }
}