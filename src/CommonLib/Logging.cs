#nullable enable
using Microsoft.Extensions.Logging;

namespace SharpHoundCommonLib
{
    internal static class Logging
    {
        internal static readonly ILoggerProvider LogProvider = new LogProvider();
        internal static ILogger Logger { get; set; } = new NoOpLogger();

        /// <summary>
        ///     Configures logging for the common library using an ILogger interface
        /// </summary>
        /// <param name="logger">ILogger interface desired for logging</param>
        public static void ConfigureLogging(ILogger logger)
        {
            Logger = logger;
        }
    }
}