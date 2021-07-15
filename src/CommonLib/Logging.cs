#nullable enable
using System;
using Microsoft.Extensions.Logging;

namespace SharpHoundCommonLib
{
    internal static class Logging
    {
        private static ILogger? Logger { get; set; }

        /// <summary>
        ///     Configures logging for the common library using an ILogger interface
        /// </summary>
        /// <param name="logger">ILogger interface desired for logging</param>
        public static void ConfigureLogging(ILogger logger)
        {
            Logger = logger;
        }

        /// <summary>
        ///     Outputs a debug message
        /// </summary>
        /// <param name="message"></param>
        /// <param name="args"></param>
        internal static void Debug(string? message, params object?[] args)
        {
            Logger?.Log(LogLevel.Debug, "[CommonLib]{Message}", message);
        }

        /// <summary>
        ///     ///
        ///     <summary>
        ///         Outputs a regular log message
        ///     </summary>
        ///     <param name="message"></param>
        ///     <param name="args"></param>
        /// </summary>
        /// <param name="message"></param>
        /// <param name="args"></param>
        internal static void Info(string? message, params object?[] args)
        {
            Logger?.Log(LogLevel.Information, "[CommonLib]{Message}", message);
        }

        internal static void Trace(string? message, params object?[] args)
        {
            Logger?.Log(LogLevel.Trace, "[CommonLib]{Message}", message);
        }

        /// <summary>
        ///     Outputs a log message with a configurable level
        /// </summary>
        /// <param name="level"></param>
        /// <param name="message"></param>
        /// <param name="args"></param>
        internal static void Log(LogLevel level, string? message, params object?[] args)
        {
            Logger?.Log(level, message, args);
        }

        private static string FormatLog(LogLevel level, string message)
        {
            var time = DateTime.Now;
            return $"[CommonLib]{time:O}|{level.ToString().ToUpper()}|{message}";
        }
    }
}