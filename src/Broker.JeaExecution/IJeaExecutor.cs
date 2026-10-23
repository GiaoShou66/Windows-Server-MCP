using Broker.Core;
using Broker.Registry;

namespace Broker.JeaExecution;

/// <summary>
/// Result of one JEA invocation. <paramref name="Reason"/> is a short, client-safe reject
/// code (never a stack trace or raw PowerShell error text); null means "generic failure".
/// </summary>
public sealed record JeaInvocationResult(
    bool Success, int ExitCode, string PayloadJson, long DurationMs,
    DateTimeOffset StartedUtc, DateTimeOffset EndedUtc, string? Reason = null);

/// <summary>
/// Single seam through which the broker reaches PowerShell. The pipeline depends on this
/// interface so tests can prove that a denied request never reaches execution, and so
/// resource limits can be applied by a decorator without touching the WSMan client.
/// </summary>
public interface IJeaExecutor
{
    Task<JeaInvocationResult> InvokeAsync(
        ToolManifest tool,
        IReadOnlyDictionary<string, object> argv,
        CallContext context,
        CancellationToken ct);
}
