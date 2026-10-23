using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text.Json;
using Broker.Core;
using Broker.Registry;
using Microsoft.Extensions.Logging;

[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("Broker.Tests")]

namespace Broker.JeaExecution;

public sealed record JeaInvocationResult(
    bool Success, int ExitCode, string PayloadJson, long DurationMs, DateTimeOffset StartedUtc, DateTimeOffset EndedUtc);

/// <summary>
/// Executes a tool by opening a constrained PSSession to its JEA endpoint on the local
/// host and invoking the single mapped cmdlet with a typed argument dictionary.
/// The broker never calls cmdlets directly — all execution crosses the JEA boundary.
/// </summary>
public sealed class JeaEndpointClient
{
    private readonly ILogger<JeaEndpointClient> _logger;

    public JeaEndpointClient(ILogger<JeaEndpointClient> logger) => _logger = logger;

    public async Task<JeaInvocationResult> InvokeAsync(
        ToolManifest tool,
        IReadOnlyDictionary<string, object> argv,
        CallContext context,
        CancellationToken ct)
    {
        var start = DateTimeOffset.UtcNow;

        // Loopback WSMan connection into the named JEA session configuration.
        var connInfo = new WSManConnectionInfo
        {
            ComputerName = "localhost",
            ShellUri = $"http://schemas.microsoft.com/powershell/{tool.JeaMapping.EndpointName}",
            AuthenticationMechanism = AuthenticationMechanism.Kerberos
        };

        using var runspace = RunspaceFactory.CreateRunspace(connInfo);

        return await Task.Run(() =>
        {
            try
            {
                runspace.Open();
                using var ps = PowerShell.Create();
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
                        JsonSerializer.Serialize(new { error = "jea-cancelled" }), durationMs, start, ended);

                if (ps.HadErrors)
                {
                    var err = string.Join("; ", ps.Streams.Error.Select(e => e.ToString()));
                    _logger.LogWarning("JEA invocation errors for {Tool}: {Err}", tool.ToolId, err);
                    return new JeaInvocationResult(false, 1,
                        JsonSerializer.Serialize(new { error = err }), durationMs, start, ended);
                }

                var materialized = output.Select(ToSerializable).ToArray();
                var payload = JsonSerializer.Serialize(materialized);
                return new JeaInvocationResult(true, 0, payload, durationMs, start, ended);
            }
            catch (Exception ex)
            {
                var ended = DateTimeOffset.UtcNow;
                var durationMs = (long)(ended - start).TotalMilliseconds;
                _logger.LogError(ex, "JEA invocation failed for {Tool}", tool.ToolId);
                return new JeaInvocationResult(false, 2,
                    JsonSerializer.Serialize(new { error = "jea-invocation-failed" }), durationMs, start, ended);
            }
            finally
            {
                if (runspace.RunspaceStateInfo.State == RunspaceState.Opened)
                    runspace.Close();
            }
        }, ct);
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
