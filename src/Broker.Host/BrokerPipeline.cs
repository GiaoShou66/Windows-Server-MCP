using System.Collections.Concurrent;
using System.Text.Json;
using Broker.Audit;
using Broker.Core;
using Broker.JeaExecution;
using Broker.Policy;
using Broker.Registry;
using Broker.Transport;
using Microsoft.Extensions.Logging;

namespace Broker.Host;

/// <summary>
/// The fail-closed call pipeline. Gates run in a fixed order; any gate that does not
/// explicitly allow terminates the call. Order (design 6.1):
///   1 manifest lookup  2 signature re-check  3 risk tier  4 parameter validate
///   5 untrusted-source gate  6 rate limit  7 elicitation  8 JEA invoke
/// Audit events are emitted at the stage that concludes, success or reject.
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
    private readonly JeaEndpointClient _jea;
    private readonly TaintTracker _taint;
    private readonly CorrelationLog _correlationLog;
    private readonly ILogger<BrokerPipeline> _logger;

    // toolId -> (correlationId -> cts) for in-flight elicitations, so a revocation can
    // cancel any call currently waiting on human approval for that tool.
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, CancellationTokenSource>> _inflightElicitations = new(StringComparer.Ordinal);

    public BrokerPipeline(
        ManifestStore manifest, ISignatureVerifier signatures, ParameterValidator paramValidator,
        UntrustedSourceGate untrustedGate, RateLimiter rateLimiter, AmsiScanner amsi,
        ConsentEngine consent, ArgvBuilder argvBuilder, JeaEndpointClient jea,
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
        // 1 — manifest lookup
        var tool = _manifest.Get(request.ToolId);
        if (tool is null) return Reject(context, "unknown-or-revoked-tool");

        // 2 — signature re-check at call time
        if (!_signatures.Verify(tool)) return Reject(context, "signature-verification-failed");

        // 3 — risk tier known (enum resolves; used downstream)
        var tier = tool.RiskTier;

        // 3b — caller taint: a caller that recently received untrusted external data may not
        //       drive a mutating tool until the taint window expires (prompt-injection defense).
        if (tier is RiskTier.Write or RiskTier.Destructive && _taint.IsTainted(context.CallerSid))
            return Reject(context, "caller-tainted");

        // 4 — parameter allowlist validation (broker-side defense in depth)
        var paramCheck = _paramValidator.Validate(tool, request.Parameters);
        if (!paramCheck.Allowed) return Reject(context, paramCheck.Reason!);

        // AMSI scan of validated args
        var amsiCheck = _amsi.Scan(context.CorrelationId, request.Parameters);
        if (!amsiCheck.Allowed) return Reject(context, amsiCheck.Reason!);

        // 5 — untrusted-source gate (hard, no elicitation override)
        var untrusted = _untrustedGate.Evaluate(tool);
        if (!untrusted.Allowed) return Reject(context, untrusted.Reason!);

        // 6 — rate limit
        var rate = _rateLimiter.Check(context.CallerSid, tier);
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

        // 7 — elicitation for write/destructive
        if (tool.ElicitationRequired)
        {
            var paramHash = ConsentEngine.HashParameters(request.Parameters);

            // Register a cancellation source so a revocation of this tool mid-wait aborts it.
            using var revokeCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var byCorr = _inflightElicitations.GetOrAdd(tool.ToolId, _ => new(StringComparer.Ordinal));
            byCorr[context.CorrelationId] = revokeCts;

            ElicitationReply reply;
            try
            {
                reply = await elicitation.RequestAsync(
                    new ElicitationContext(context.CorrelationId, tool.ToolId, context.CallerSid, paramHash),
                    revokeCts.Token);
            }
            catch (OperationCanceledException)
            {
                var revoked = _manifest.Get(tool.ToolId) is null;
                return Reject(context, revoked ? "tool-revoked-mid-elicitation" : "elicitation-timeout-or-disconnect");
            }
            finally
            {
                byCorr.TryRemove(context.CorrelationId, out _);
            }

            var verdict = _consent.Verify(
                context.CorrelationId, paramHash, context.CallerSid,
                reply.CorrelationId, reply.ParamHash, reply.Approved, reply.DecidedBySid);

            McpBrokerEventSource.Log.ElicitationDecision(
                context.CorrelationId, reply.DecidedBySid, reply.Approved, DateTimeOffset.UtcNow.UtcTicks);

            if (!verdict.Allowed) return Reject(context, verdict.Reason!);
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

        var result = await _jea.InvokeAsync(tool, argv, context, ct);

        McpBrokerEventSource.Log.JeaInvocationCompleted(
            context.CorrelationId, tool.JeaMapping.EndpointName, result.ExitCode,
            result.DurationMs, DateTimeOffset.UtcNow.UtcTicks);

        if (!result.Success) return ToolCallResult.Rejected("jea-execution-error");

        // Out-of-band correlation: record (correlationId, endpoint, window) so the aggregator
        // can later join this call to its JEA transcript without anything run in-session.
        _correlationLog.Append(new CorrelationEntry(
            context.CorrelationId, context.CallerSid, tool.ToolId,
            tool.JeaMapping.EndpointName, result.StartedUtc, result.EndedUtc));

        // Taint the caller if this tool's output may carry untrusted external data.
        if (tool.UntrustedInputSources.Count > 0)
            _taint.MarkTainted(context.CallerSid);

        var masked = MaskFields(result.PayloadJson, tool.MaskedFields);
        return ToolCallResult.Ok(masked);
    }

    private ToolCallResult Reject(CallContext ctx, string reason)
    {
        McpBrokerEventSource.Log.ToolCallRejected(
            ctx.CorrelationId, ctx.CallerSid, ctx.ToolId, reason, DateTimeOffset.UtcNow.UtcTicks);
        _logger.LogWarning("Rejected {Tool} ({Corr}): {Reason}", ctx.ToolId, ctx.CorrelationId, reason);
        return ToolCallResult.Rejected(reason);
    }

    /// <summary>Redacts configured output fields before the payload leaves the broker.</summary>
    private static string MaskFields(string payloadJson, IReadOnlyCollection<string> maskedFields)
    {
        if (maskedFields.Count == 0) return payloadJson;

        try
        {
            using var doc = JsonDocument.Parse(payloadJson);
            var masked = MaskElement(doc.RootElement, maskedFields);
            return JsonSerializer.Serialize(masked);
        }
        catch (JsonException)
        {
            return payloadJson;
        }
    }

    private static object? MaskElement(JsonElement el, IReadOnlyCollection<string> fields)
    {
        switch (el.ValueKind)
        {
            case JsonValueKind.Object:
                var obj = new Dictionary<string, object?>();
                foreach (var prop in el.EnumerateObject())
                    obj[prop.Name] = fields.Contains(prop.Name, StringComparer.OrdinalIgnoreCase)
                        ? "***MASKED***"
                        : MaskElement(prop.Value, fields);
                return obj;

            case JsonValueKind.Array:
                return el.EnumerateArray().Select(e => MaskElement(e, fields)).ToArray();

            case JsonValueKind.String: return el.GetString();
            case JsonValueKind.Number: return el.GetDouble();
            case JsonValueKind.True: return true;
            case JsonValueKind.False: return false;
            default: return null;
        }
    }
}
