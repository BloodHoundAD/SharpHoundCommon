using Microsoft.Extensions.Logging;

namespace CommonLib
{
    static class Logging
    {
        internal static ILogger Logger { get; set; }
        
        /// <summary>
        /// Configures logging for the common library using an ILogger interface
        /// </summary>
        /// <param name="logger">ILogger interface desired for logging</param>
        public static void ConfigureLogging(ILogger logger)
        {
            Logger = logger;
        }

        internal static void Debug(string? message, params object?[] args)
        {
            Logger?.LogDebug(message, args);
        }
        
        internal static void Log(string? message, params object?[] args)
        {
            Logger?.Log(LogLevel.Information, message, args);
        }

        internal static void Log(LogLevel level, string? message, params object?[] args)
        {
            Logger?.Log(level, message, args);
        }
    }
}