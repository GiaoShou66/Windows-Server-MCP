using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text.Json;
using Broker.Core;
using Broker.Registry;
using Microsoft.Extensions.Logging;

[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("Broker.Tests")]

namespace Broker.JeaExecution;

/// <summary>Timeouts handed to the WSMan transport so a hung remote call terminates on its own.</summary>
public sealed record JeaClientOptions(int OpenTimeoutMs = 30_000, int OperationTimeoutMs = 60_000);

/// <summary>
/// Executes a tool by opening a constrained PSSession to its JEA endpoint on the local
/// host and invoking the single mapped cmdlet with a typed argument dictionary.
/// The broker never calls cmdlets directly — all execution crosses the JEA boundary.
///
/// Concurrency is NOT limited here; wrap this in <see cref="BoundedJeaExecutor"/>. Every call
/// occupies one thread-pool thread for its full duration (the PowerShell SDK calls are
/// synchronous), which is exactly why the bounded decorator must sit in front of it.
/// </summary>
public sealed class JeaEndpointClient : IJeaExecutor
{
    private readonly ILogger<JeaEndpointClient> _logger;
    private readonly JeaClientOptions _options;

    public JeaEndpointClient(ILogger<JeaEndpointClient> logger, JeaClientOptions? options = null)
    {
        _logger = logger;
        _options = options ?? new JeaClientOptions();
    }

    public Task<JeaInvocationResult> InvokeAsync(
        ToolManifest tool,
        IReadOnlyDictionary<string, object> argv,
        CallContext context,
        CancellationToken ct)
    {
        var start = DateTimeOffset.UtcNow;
        // The cancellation token is deliberately not given to Task.Run: a token already
        // cancelled at scheduling time would surface as an exception instead of a result.
        return Task.Run(() => InvokeBlocking(tool, argv, ct, start), CancellationToken.None);
    }

    private JeaInvocationResult InvokeBlocking(
        ToolManifest tool, IReadOnlyDictionary<string, object> argv, CancellationToken ct, DateTimeOffset start)
    {
        Runspace? runspace = null;
        PowerShell? ps = null;
        try
        {
            if (ct.IsCancellationRequested)
                return Failed(start, 3, "jea-cancelled", "jea-cancelled");

            // Loopback WSMan connection into the named JEA session configuration.
            var connInfo = new WSManConnectionInfo
            {
                ComputerName = "localhost",
                ShellUri = $"http://schemas.microsoft.com/powershell/{tool.JeaMapping.EndpointName}",
                AuthenticationMechanism = AuthenticationMechanism.Kerberos,
                OpenTimeout = _options.OpenTimeoutMs,
                OperationTimeout = _options.OperationTimeoutMs
            };

            runspace = RunspaceFactory.CreateRunspace(connInfo);
            runspace.Open();

            ps = PowerShell.Create();
            ps.Runspace = runspace;
            using var cancellation = ct.Register(() =>
            {
                try { ps.Stop(); }
                catch (Exception ex) { _logger.LogDebug(ex, "Unable to stop JEA invocation for {Tool}", tool.ToolId); }
            });

            // No in-session marker: the endpoint runs in NoLanguage mode and exposes only
            // the single mapped cmdlet, so neither AddScript nor Write-Verbose is permitted.
            // Correlation is done out-of-band by the broker via the correlation log
            // (correlationId + endpoint + start/end window) joined to the JEA transcript.
            ps.AddCommand(tool.JeaMapping.Cmdlet);
            foreach (var (name, value) in argv)
                ps.AddParameter(name, value);

            var output = ps.Invoke();
            var ended = DateTimeOffset.UtcNow;
            var durationMs = (long)(ended - start).TotalMilliseconds;

            if (ct.IsCancellationRequested)
                return new JeaInvocationResult(false, 3,
                    JsonSerializer.Serialize(new { error = "jea-cancelled" }), durationMs, start, ended, "jea-cancelled");

            if (ps.HadErrors)
            {
                // Raw error text can echo caller-supplied values or directory data: log it
                // locally, never return it.
                var err = string.Join("; ", ps.Streams.Error.Select(e => e.ToString()));
                _logger.LogWarning("JEA invocation errors for {Tool}: {Err}", tool.ToolId, err);
                return new JeaInvocationResult(false, 1,
                    JsonSerializer.Serialize(new { error = "jea-execution-error" }), durationMs, start, ended);
            }

            var materialized = output.Select(ToSerializable).ToArray();
            var payload = JsonSerializer.Serialize(materialized);
            return new JeaInvocationResult(true, 0, payload, durationMs, start, ended);
        }
        catch (Exception ex)
        {
            // Includes runspace creation/open failures (e.g. WSMan unavailable) and the
            // PipelineStoppedException raised when Stop() interrupts a running pipeline.
            _logger.LogError(ex, "JEA invocation failed for {Tool}", tool.ToolId);
            return ct.IsCancellationRequested
                ? Failed(start, 3, "jea-cancelled", "jea-cancelled")
                : Failed(start, 2, "jea-invocation-failed", null);
        }
        finally
        {
            try { ps?.Dispose(); } catch (Exception ex) { _logger.LogDebug(ex, "PowerShell dispose failed"); }
            try { runspace?.Dispose(); } catch (Exception ex) { _logger.LogDebug(ex, "Runspace dispose failed"); }
        }
    }

    private static JeaInvocationResult Failed(DateTimeOffset start, int exitCode, string error, string? reason)
    {
        var ended = DateTimeOffset.UtcNow;
        return new JeaInvocationResult(false, exitCode,
            JsonSerializer.Serialize(new { error }), (long)(ended - start).TotalMilliseconds, start, ended, reason);
    }

    /// <summary>
    /// Converts PowerShell output into plain CLR objects that System.Text.Json can serialize.
    /// A raw PSObject/PSCustomObject serializes to "{}", so property bags are flattened to
    /// dictionaries and wrapped primitives are unwrapped to their base value.
    /// </summary>
    internal static object? ToSerializable(object? o)
    {
        switch (o)
        {
            case null:
                return null;

            case PSObject ps:
                if (ps.BaseObject is PSCustomObject)
                {
                    var bag = new Dictionary<string, object?>();
                    foreach (var prop in ps.Properties)
                        bag[prop.Name] = ToSerializable(prop.Value);
                    return bag;
                }
                return ToSerializable(ps.BaseObject);

            case string s:
                return s;

            case System.Collections.IDictionary dict:
                var map = new Dictionary<string, object?>();
                foreach (System.Collections.DictionaryEntry e in dict)
                    map[e.Key?.ToString() ?? ""] = ToSerializable(e.Value);
                return map;

            case System.Collections.IEnumerable en:
                return en.Cast<object?>().Select(ToSerializable).ToArray();

            default:
                return o;
        }
    }
}
