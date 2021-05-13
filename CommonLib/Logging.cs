#nullable enable
using Microsoft.Extensions.Logging;

namespace SharpHoundCommonLib
{
    internal static class Logging
    {
        private static ILogger Logger { get; set; }
        
        /// <summary>
        /// Configures logging for the common library using an ILogger interface
        /// </summary>
        /// <param name="logger">ILogger interface desired for logging</param>
        public static void ConfigureLogging(ILogger logger)
        {
            Logger = logger;
        }

        /// <summary>
        /// Outputs a debug message
        /// </summary>
        /// <param name="message"></param>
        /// <param name="args"></param>
        internal static void Debug(string? message, params object?[] args)
        {
            Logger?.LogDebug(message, args);
        }
        
        /// <summary>
        /// /// <summary>
        /// Outputs a regular log message
        /// </summary>
        /// <param name="message"></param>
        /// <param name="args"></param>
        /// </summary>
        /// <param name="message"></param>
        /// <param name="args"></param>
        internal static void Log(string? message, params object?[] args)
        {
            Logger?.Log(LogLevel.Information, message, args);
        }

        /// <summary>
        /// Outputs a log message with a configurable level
        /// </summary>
        /// <param name="level"></param>
        /// <param name="message"></param>
        /// <param name="args"></param>
        internal static void Log(LogLevel level, string? message, params object?[] args)
        {
            Logger?.Log(level, message, args);
        }
    }
}