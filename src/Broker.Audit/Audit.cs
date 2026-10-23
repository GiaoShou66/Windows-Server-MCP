using System.Diagnostics.Tracing;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Broker.Audit;

/// <summary>
/// Structured ETW provider. One strongly-typed event per lifecycle point.
/// parametersJson is always post-validation — a payload that failed allowlist checks
/// never lands in the trace (rejections log a reason, not content).
/// </summary>
[EventSource(Name = "McpBroker")]
public sealed class McpBrokerEventSource : EventSource
{
    public static readonly McpBrokerEventSource Log = new();
    private McpBrokerEventSource() { }

    [Event(1, Level = EventLevel.Informational, Message = "Tool call requested")]
    public void ToolCallRequested(
        string correlationId, string callerSid, string toolId, string riskTier,
        string parametersJson, long timestampUtcTicks)
        => WriteEvent(1, correlationId, callerSid, toolId, riskTier, parametersJson, timestampUtcTicks);

    [Event(2, Level = EventLevel.Informational, Message = "Elicitation decision recorded")]
    public void ElicitationDecision(
        string correlationId, string decidedBySid, bool approved, long timestampUtcTicks)
        => WriteEvent(2, correlationId, decidedBySid, approved, timestampUtcTicks);

    [Event(3, Level = EventLevel.Informational, Message = "JEA invocation completed")]
    public void JeaInvocationCompleted(
        string correlationId, string endpointName, int exitCode, long durationMs, long timestampUtcTicks)
        => WriteEvent(3, correlationId, endpointName, exitCode, durationMs, timestampUtcTicks);

    [Event(4, Level = EventLevel.Error, Message = "Tool call rejected")]
    public void ToolCallRejected(
        string correlationId, string callerSid, string toolId, string reason, long timestampUtcTicks)
        => WriteEvent(4, correlationId, callerSid, toolId, reason, timestampUtcTicks);

    [Event(5, Level = EventLevel.Warning, Message = "Rate limit breached")]
    public void RateLimitBreached(
        string correlationId, string callerSid, string toolId, long timestampUtcTicks)
        => WriteEvent(5, correlationId, callerSid, toolId, timestampUtcTicks);
}

/// <summary>One invocation the broker dispatched, appended to the correlation log as JSONL.</summary>
public sealed record CorrelationEntry(
    string CorrelationId,
    string CallerSid,
    string ToolId,
    string EndpointName,
    DateTimeOffset StartUtc,
    DateTimeOffset EndUtc);

/// <summary>
/// Append-only JSONL log the broker writes per JEA invocation. It is the out-of-band
/// correlation source: the JEA session runs NoLanguage and exposes only one cmdlet, so
/// nothing can be written into the transcript from inside the session. The broker records
/// (correlationId, endpoint, start/end) here and the aggregator joins it to transcripts.
/// </summary>
public sealed class CorrelationLog
{
    private readonly string _path;
    private readonly object _lock = new();

    public CorrelationLog(string path)
    {
        _path = path;
        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
    }

    public void Append(CorrelationEntry entry)
    {
        var line = JsonSerializer.Serialize(entry);
        lock (_lock) File.AppendAllText(_path, line + Environment.NewLine);
    }

    public IReadOnlyList<CorrelationEntry> ReadSince(DateTimeOffset since)
    {
        if (!File.Exists(_path)) return Array.Empty<CorrelationEntry>();

        var result = new List<CorrelationEntry>();
        lock (_lock)
        {
            foreach (var line in File.ReadLines(_path))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                CorrelationEntry? e = null;
                try { e = JsonSerializer.Deserialize<CorrelationEntry>(line); }
                catch (JsonException) { }
                if (e is not null && e.EndUtc >= since) result.Add(e);
            }
        }
        return result;
    }
}

public sealed record TranscriptRecord(
    string EndpointName,
    string TranscriptFilePath,
    DateTimeOffset StartUtc,
    DateTimeOffset LastWriteUtc);

public sealed record CorrelatedTranscript(
    string CorrelationId,
    string ToolId,
    string CallerSid,
    string EndpointName,
    string TranscriptFilePath);

/// <summary>
/// Reads JEA transcripts and joins them to correlation-log entries by endpoint and time
/// window. The ETW event stream (which carries the same correlationId) is the primary
/// audit record; this join reconnects the on-disk transcript body to that id for forensics.
/// </summary>
public sealed class TranscriptAggregator
{
    private static readonly TimeSpan Skew = TimeSpan.FromSeconds(5);

    private readonly string _transcriptDir;
    private readonly ILogger<TranscriptAggregator> _logger;

    public TranscriptAggregator(string transcriptDir, ILogger<TranscriptAggregator> logger)
    {
        _transcriptDir = transcriptDir;
        _logger = logger;
    }

    public IEnumerable<TranscriptRecord> CollectSince(DateTimeOffset since)
    {
        if (!Directory.Exists(_transcriptDir)) yield break;

        foreach (var file in Directory.EnumerateFiles(_transcriptDir, "PowerShell_transcript*.txt"))
        {
            var info = new FileInfo(file);
            if (info.LastWriteTimeUtc < since.UtcDateTime) continue;

            string endpoint = "unknown";
            DateTimeOffset startUtc = new(info.LastWriteTimeUtc, TimeSpan.Zero);
            try
            {
                foreach (var line in File.ReadLines(file).Take(40))
                {
                    if (line.StartsWith("Configuration Name:", StringComparison.OrdinalIgnoreCase))
                        endpoint = line.Split(':', 2)[1].Trim();

                    if (line.StartsWith("Start time:", StringComparison.OrdinalIgnoreCase) &&
                        DateTime.TryParse(line.Split(':', 2)[1].Trim(), out var parsed))
                        startUtc = new DateTimeOffset(parsed.ToUniversalTime(), TimeSpan.Zero);
                }
            }
            catch (IOException ex)
            {
                _logger.LogDebug(ex, "Transcript still locked, skipping: {File}", file);
                continue;
            }

            yield return new TranscriptRecord(endpoint, file, startUtc,
                new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero));
        }
    }

    /// <summary>Joins transcripts to correlation entries on endpoint + overlapping time window.</summary>
    public IEnumerable<CorrelatedTranscript> Correlate(DateTimeOffset since, IEnumerable<CorrelationEntry> entries)
    {
        var byEndpoint = entries
            .GroupBy(e => e.EndpointName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);

        foreach (var t in CollectSince(since))
        {
            if (!byEndpoint.TryGetValue(t.EndpointName, out var candidates)) continue;

            var matches = candidates.Where(e =>
                t.StartUtc >= e.StartUtc - Skew && t.StartUtc <= e.EndUtc + Skew);

            var match = matches.Take(2).ToArray();
            if (match.Length == 1)
                yield return new CorrelatedTranscript(
                    match[0].CorrelationId, match[0].ToolId, match[0].CallerSid,
                    t.EndpointName, t.TranscriptFilePath);
            else if (match.Length > 1)
                _logger.LogWarning("Ambiguous transcript correlation for {Transcript}; {Count} candidates",
                    t.TranscriptFilePath, match.Length);
        }
    }
}
