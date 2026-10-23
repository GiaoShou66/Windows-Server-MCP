namespace Broker.Core;

/// <summary>
/// Risk classification for a tool. Read passes by default; Write and Destructive
/// require human confirmation via elicitation before the JEA invocation runs.
/// </summary>
public enum RiskTier
{
    Read = 0,
    Write = 1,
    Destructive = 2
}

/// <summary>Categories of data that may arrive from outside the trust boundary.</summary>
public enum UntrustedSource
{
    AdAttribute,
    FileContent,
    NetworkResponse
}

/// <summary>
/// Per-call correlation and identity context. CorrelationId is server-generated
/// (never client-supplied) so an approved id cannot be replayed to skip elicitation.
/// </summary>
public sealed record CallContext
{
    public required string CorrelationId { get; init; }
    public required string CallerSid { get; init; }
    public required string ToolId { get; init; }
    public DateTimeOffset ReceivedUtc { get; init; } = DateTimeOffset.UtcNow;

    public static CallContext New(string callerSid, string toolId) => new()
    {
        CorrelationId = Guid.NewGuid().ToString("N"),
        CallerSid = callerSid,
        ToolId = toolId
    };
}

/// <summary>A single tool invocation request decoded from the pipe.</summary>
public sealed record ToolCallRequest
{
    public required string ToolId { get; init; }
    public Dictionary<string, string> Parameters { get; init; } = new();
}

/// <summary>Result returned to the client over the pipe.</summary>
public sealed record ToolCallResult
{
    public required bool Success { get; init; }
    public string? RejectReason { get; init; }
    public string? PayloadJson { get; init; }

    public static ToolCallResult Ok(string payloadJson) => new() { Success = true, PayloadJson = payloadJson };
    public static ToolCallResult Rejected(string reason) => new() { Success = false, RejectReason = reason };
}

/// <summary>Outcome of a policy gate. Fail-closed: anything not explicitly allowed is denied.</summary>
public sealed record PolicyDecision
{
    public required bool Allowed { get; init; }
    public string? Reason { get; init; }
    public bool RequiresElicitation { get; init; }

    public static PolicyDecision Allow(bool requiresElicitation = false) =>
        new() { Allowed = true, RequiresElicitation = requiresElicitation };

    public static PolicyDecision Deny(string reason) => new() { Allowed = false, Reason = reason };
}
