using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Nodes;
using Broker.Audit;
using Broker.Core;
using Broker.JeaExecution;
using Broker.Policy;
using Broker.Registry;
using Broker.Transport;
using Microsoft.Extensions.Logging;

[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("Broker.Tests")]

namespace Broker.Host;

/// <summary>
/// The fail-closed call pipeline. Gates run in a fixed order; any gate that does not
/// explicitly allow terminates the call, and so does any gate that throws. Order:
///   0 caller identity  1 manifest lookup  2 signature re-check  3 risk tier / caller taint
///   4 parameter validate  4b AMSI  5 untrusted-source gate  6 rate limit
///   7 elicitation (then taint / revocation / signature re-checked)  8 JEA invoke  9 output masking
/// Audit events are emitted at the stage that concludes, success or reject.
///
/// Nothing in here lets an exception turn into "allowed": a throwing gate is a rejection, an
/// executor that throws is a rejection, and an audit sink that fails after execution is logged
/// but never hides a result for work that already happened.
/// </summary>
public sealed class BrokerPipeline : IToolCallDispatcher
{
    private readonly ManifestStore _manifest;
    private readonly ISignatureVerifier _signatures;
    private readonly ParameterValidator _paramValidator;
    private readonly UntrustedSourceGate _untrustedGate;
    private readonly RateLimiter _rateLimiter;
    private readonly AmsiScanner _amsi;
    private readonly ConsentEngine _consent;
    private readonly ArgvBuilder _argvBuilder;
    private readonly IJeaExecutor _jea;
    private readonly TaintTracker _taint;
    private readonly CorrelationLog _correlationLog;
    private readonly ILogger<BrokerPipeline> _logger;

    // toolId -> (correlationId -> cts) for in-flight elicitations, so a revocation can
    // cancel any call currently waiting on human approval for that tool.
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, CancellationTokenSource>> _inflightElicitations = new(StringComparer.Ordinal);

    public BrokerPipeline(
        ManifestStore manifest, ISignatureVerifier signatures, ParameterValidator paramValidator,
        UntrustedSourceGate untrustedGate, RateLimiter rateLimiter, AmsiScanner amsi,
        ConsentEngine consent, ArgvBuilder argvBuilder, IJeaExecutor jea,
        TaintTracker taint, CorrelationLog correlationLog, ILogger<BrokerPipeline> logger)
    {
        _manifest = manifest;
        _signatures = signatures;
        _paramValidator = paramValidator;
        _untrustedGate = untrustedGate;
        _rateLimiter = rateLimiter;
        _amsi = amsi;
        _consent = consent;
        _argvBuilder = argvBuilder;
        _jea = jea;
        _taint = taint;
        _correlationLog = correlationLog;
        _logger = logger;

        _manifest.ToolsRevoked += OnToolsRevoked;
    }

    private void OnToolsRevoked(IReadOnlyCollection<string> revokedToolIds)
    {
        foreach (var toolId in revokedToolIds)
        {
            if (!_inflightElicitations.TryGetValue(toolId, out var byCorr)) continue;
            foreach (var cts in byCorr.Values)
            {
                try { cts.Cancel(); } catch (ObjectDisposedException) { }
            }
            _logger.LogWarning("Cancelled in-flight elicitations for revoked tool {Tool}", toolId);
        }
    }

    public async Task<ToolCallResult> DispatchAsync(
        ToolCallRequest request, CallContext context, ElicitationChannel elicitation, CancellationToken ct)
    {
        // 0 — a call with no authenticated caller identity is never processed.
        if (string.IsNullOrWhiteSpace(context.CallerSid))
            return Reject(context, "caller-identity-missing");

        if (!string.Equals(context.ToolId, request.ToolId, StringComparison.Ordinal))
            return Reject(context, "context-tool-mismatch");

        // 1 — manifest lookup
        var tool = _manifest.Get(request.ToolId);
        if (tool is null) return Reject(context, "unknown-or-revoked-tool");

        // 2 — signature re-check at call time
        if (!SignatureValid(tool)) return Reject(context, "signature-verification-failed");

        // 3 — risk tier (unrecognized tiers resolve to the most restrictive tier)
        var tier = tool.RiskTier;

        // 3b — caller taint: a caller that recently received untrusted external data may not
        //       drive a mutating tool until the taint window expires (prompt-injection defense).
        if (tier is RiskTier.Write or RiskTier.Destructive && _taint.IsTainted(context.CallerSid))
            return Reject(context, "caller-tainted");

        // 4 — parameter allowlist validation (broker-side defense in depth)
        var paramCheck = Guarded(() => _paramValidator.Validate(tool, request.Parameters), "parameter-validation-error");
        if (!paramCheck.Allowed) return Reject(context, paramCheck.Reason!);

        // 4b — AMSI scan of validated args: a supplementary signal, never a substitute for the gates.
        var amsiCheck = Guarded(() => _amsi.Scan(context.CorrelationId, request.Parameters), "amsi-scan-error");
        if (!amsiCheck.Allowed) return Reject(context, amsiCheck.Reason!);

        // 5 — untrusted-source gate (hard, no elicitation override)
        var untrusted = Guarded(() => _untrustedGate.Evaluate(tool), "untrusted-source-gate-error");
        if (!untrusted.Allowed) return Reject(context, untrusted.Reason!);

        // 6 — rate limit (per caller and global)
        var rate = Guarded(() => _rateLimiter.Check(context.CallerSid, tier), "rate-limit-error");
        if (!rate.Allowed)
        {
            McpBrokerEventSource.Log.RateLimitBreached(
                context.CorrelationId, context.CallerSid, tool.ToolId, DateTimeOffset.UtcNow.UtcTicks);
            return Reject(context, rate.Reason!);
        }

        // Audit: request accepted into execution path (post-validation params only)
        McpBrokerEventSource.Log.ToolCallRequested(
            context.CorrelationId, context.CallerSid, tool.ToolId, tier.ToString(),
            JsonSerializer.Serialize(request.Parameters), DateTimeOffset.UtcNow.UtcTicks);

        // 7 — elicitation for write/destructive (and any tool that opts in)
        if (tool.ElicitationRequired)
        {
            var rejection = await ElicitAsync(tool, tier, request, context, elicitation, ct);
            if (rejection is not null) return rejection;
        }

        // 8 — JEA invoke via argv array (never a composed string)
        IReadOnlyDictionary<string, object> argv;
        try
        {
            argv = _argvBuilder.Build(tool, request.Parameters);
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogError(ex, "ArgvBuilder refused call for {Tool}", tool.ToolId);
            return Reject(context, "argv-build-refused");
        }

        // The output of an untrusted-source tool is about to reach this caller. Taint now, so a
        // write that arrives while the read is still running is already blocked, and so a failed
        // read cannot be used to dodge the window.
        if (tool.UntrustedInputSources.Count > 0)
            _taint.MarkTainted(context.CallerSid);

        JeaInvocationResult result;
        try
        {
            result = await _jea.InvokeAsync(tool, argv, context, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return Reject(context, "jea-cancelled");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "JEA executor threw for {Tool} ({Corr})", tool.ToolId, context.CorrelationId);
            return Reject(context, "jea-execution-error");
        }

        McpBrokerEventSource.Log.JeaInvocationCompleted(
            context.CorrelationId, tool.JeaMapping.EndpointName, result.ExitCode,
            result.DurationMs, DateTimeOffset.UtcNow.UtcTicks);

        if (!result.Success) return ToolCallResult.Rejected(result.Reason ?? "jea-execution-error");

        // Out-of-band correlation: record (correlationId, endpoint, window) so the aggregator
        // can later join this call to its JEA transcript without anything run in-session.
        // The work has already happened; a failing log must not hide its result.
        try
        {
            _correlationLog.Append(new CorrelationEntry(
                context.CorrelationId, context.CallerSid, tool.ToolId,
                tool.JeaMapping.EndpointName, result.StartedUtc, result.EndedUtc));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Correlation log append failed for {Corr}; the call itself completed", context.CorrelationId);
        }

        // Refresh the window from the moment the data is actually delivered.
        if (tool.UntrustedInputSources.Count > 0)
            _taint.MarkTainted(context.CallerSid);

        // 9 — output masking. Failing to mask is a failure to return anything, never a pass-through.
        if (!TryMask(result.PayloadJson, tool.MaskedFields, out var masked))
        {
            _logger.LogError("Output masking failed for {Tool} ({Corr}); payload withheld", tool.ToolId, context.CorrelationId);
            return Reject(context, "output-masking-failed");
        }

        return ToolCallResult.Ok(masked);
    }

    /// <summary>Returns null when the call is approved and still allowed; otherwise the rejection.</summary>
    private async Task<ToolCallResult?> ElicitAsync(
        ToolManifest tool, RiskTier tier, ToolCallRequest request, CallContext context,
        ElicitationChannel elicitation, CancellationToken ct)
    {
        // The hash binds the approval to this tool, this caller and these exact parameters
        // (which carry the target), so it cannot authorize any other operation.
        var paramHash = ConsentEngine.HashOperation(tool.ToolId, context.CallerSid, request.Parameters);

        // Register a cancellation source so a revocation of this tool mid-wait aborts it.
        using var revokeCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var byCorr = _inflightElicitations.GetOrAdd(tool.ToolId, _ => new(StringComparer.Ordinal));
        byCorr[context.CorrelationId] = revokeCts;

        ElicitationReply reply;
        try
        {
            reply = await elicitation.RequestAsync(
                new ElicitationContext(context.CorrelationId, tool.ToolId, context.CallerSid, paramHash, request.Parameters),
                revokeCts.Token);
        }
        catch (OperationCanceledException)
        {
            var revoked = _manifest.Get(tool.ToolId) is null;
            return Reject(context, revoked ? "tool-revoked-mid-elicitation" : "elicitation-timeout-or-disconnect");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Elicitation failed for {Tool} ({Corr})", tool.ToolId, context.CorrelationId);
            return Reject(context, "elicitation-failed");
        }
        finally
        {
            byCorr.TryRemove(context.CorrelationId, out _);
        }

        PolicyDecision verdict;
        try
        {
            verdict = _consent.Verify(
                context.CorrelationId, paramHash, context.CallerSid,
                reply.CorrelationId, reply.ParamHash, reply.Approved, reply.DecidedBySid,
                tool.ToolId, reply.ToolId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Consent verification threw for {Tool} ({Corr})", tool.ToolId, context.CorrelationId);
            verdict = PolicyDecision.Deny("consent-verification-error");
        }

        McpBrokerEventSource.Log.ElicitationDecision(
            context.CorrelationId, reply.DecidedBySid ?? string.Empty, reply.Approved, DateTimeOffset.UtcNow.UtcTicks);

        if (!verdict.Allowed) return Reject(context, verdict.Reason!);

        // Time passed while a human decided. Authorization state may have changed, and an approval
        // is only valid for the state it was given in, so the state is checked again right before
        // execution: still registered, signature still valid, caller still untainted.
        if (_manifest.Get(tool.ToolId) is null)
            return Reject(context, "tool-revoked-mid-elicitation");

        if (!SignatureValid(tool))
            return Reject(context, "signature-verification-failed");

        if (tier is RiskTier.Write or RiskTier.Destructive && _taint.IsTainted(context.CallerSid))
            return Reject(context, "caller-tainted");

        return null;
    }

    private bool SignatureValid(ToolManifest tool)
    {
        try
        {
            return _signatures.Verify(tool);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Signature verification threw for {Tool}; treating as invalid", tool.ToolId);
            return false;
        }
    }

    /// <summary>Runs a policy gate. A gate that throws is a denial, never an implicit allow.</summary>
    private PolicyDecision Guarded(Func<PolicyDecision> gate, string errorReason)
    {
        try
        {
            return gate();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Policy gate failed ({Reason}); denying", errorReason);
            return PolicyDecision.Deny(errorReason);
        }
    }

    private ToolCallResult Reject(CallContext ctx, string reason)
    {
        McpBrokerEventSource.Log.ToolCallRejected(
            ctx.CorrelationId, ctx.CallerSid ?? string.Empty, ctx.ToolId, reason, DateTimeOffset.UtcNow.UtcTicks);
        _logger.LogWarning("Rejected {Tool} ({Corr}): {Reason}", ctx.ToolId, ctx.CorrelationId, reason);
        return ToolCallResult.Rejected(reason);
    }

    /// <summary>
    /// Redacts configured output fields (any depth, case-insensitive). Returns false if the
    /// payload cannot be parsed or masked, in which case the caller must withhold it.
    /// Works on the JSON tree rather than re-serializing values, so numbers keep their exact text.
    /// </summary>
    internal static bool TryMask(string payloadJson, IReadOnlyCollection<string> maskedFields, out string masked)
    {
        masked = payloadJson;
        if (maskedFields.Count == 0) return true;

        try
        {
            var root = JsonNode.Parse(payloadJson);
            MaskNode(root, maskedFields);
            masked = root?.ToJsonString() ?? "null";
            return true;
        }
        catch (JsonException)
        {
            masked = string.Empty;
            return false;
        }
    }

    private static void MaskNode(JsonNode? node, IReadOnlyCollection<string> fields)
    {
        switch (node)
        {
            case JsonObject obj:
                foreach (var key in obj.Select(p => p.Key).ToArray())
                {
                    if (fields.Contains(key, StringComparer.OrdinalIgnoreCase))
                        obj[key] = "***MASKED***";
                    else
                        MaskNode(obj[key], fields);
                }
                break;

            case JsonArray arr:
                foreach (var item in arr) MaskNode(item, fields);
                break;
        }
    }
}
