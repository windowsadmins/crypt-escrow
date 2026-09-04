using System.IO;
using Serilog.Events;
using Serilog.Formatting;

namespace CryptEscrow.Services;

/// <summary>
/// Writes one JSON object per log event, in the field names every managed tool's
/// events.jsonl uses, so a fleet sweep reads this tool the same way it reads the rest.
/// </summary>
/// <remarks>
/// Written by hand rather than through a serializer because the shape is fixed and the
/// output has to stay one line per event; Serilog's own compact formatter emits its own
/// field names (@t, @m, @l), which is a different contract.
/// </remarks>
public sealed class EventJsonFormatter : ITextFormatter
{
    private readonly string _invocationId;

    public EventJsonFormatter(string invocationId)
    {
        _invocationId = invocationId;
    }

    public void Format(LogEvent logEvent, TextWriter output)
    {
        var level = LevelNameEnricher.For(logEvent.Level).Trim();
        var message = logEvent.RenderMessage();

        output.Write('{');
        WriteField(output, "timestamp", logEvent.Timestamp.ToString("yyyy-MM-ddTHH:mm:ss.fffzzz"), first: true);
        WriteField(output, "level", level);
        WriteField(output, "event_type", level == "ERROR" ? "error" : "message");
        WriteField(output, "tool", "crypt-escrow");
        WriteField(output, "pid", System.Environment.ProcessId.ToString());
        WriteField(output, "invocation_id", _invocationId);
        WriteField(output, "message", message);
        if (logEvent.Exception != null)
            WriteField(output, "error", logEvent.Exception.ToString());
        output.Write('}');
        output.Write(output.NewLine);
    }

    private static void WriteField(TextWriter output, string name, string value, bool first = false)
    {
        if (!first)
            output.Write(',');
        output.Write('"');
        output.Write(name);
        output.Write("\":\"");
        foreach (var c in value ?? string.Empty)
        {
            switch (c)
            {
                case '"': output.Write("\\\""); break;
                case '\\': output.Write("\\\\"); break;
                case '\n': output.Write("\\n"); break;
                case '\r': output.Write("\\r"); break;
                case '\t': output.Write("\\t"); break;
                default:
                    if (c < ' ') output.Write("\\u" + ((int)c).ToString("x4"));
                    else output.Write(c);
                    break;
            }
        }
        output.Write('"');
    }
}
