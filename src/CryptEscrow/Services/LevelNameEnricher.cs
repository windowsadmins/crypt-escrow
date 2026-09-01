using Serilog.Core;
using Serilog.Events;

namespace CryptEscrow.Services;

/// <summary>
/// Adds a <c>LevelName</c> property carrying the level as one of DEBUG, INFO, WARN or
/// ERROR, left-aligned and padded to five characters. Serilog's own <c>{Level:u3}</c>
/// renders INF/WRN/ERR, which is not the vocabulary the log readers expect, so the
/// file template uses this property instead.
/// </summary>
public sealed class LevelNameEnricher : ILogEventEnricher
{
    public const string PropertyName = "LevelName";

    public static string For(LogEventLevel level) => level switch
    {
        LogEventLevel.Verbose or LogEventLevel.Debug => "DEBUG",
        LogEventLevel.Information => "INFO ",
        LogEventLevel.Warning => "WARN ",
        _ => "ERROR"
    };

    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        logEvent.AddOrUpdateProperty(
            propertyFactory.CreateProperty(PropertyName, For(logEvent.Level)));
    }
}
