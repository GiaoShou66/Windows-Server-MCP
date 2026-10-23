using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Broker.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("Broker.Tests")]

namespace Broker.Transport;

/// <summary>
/// Pipeline entry point implemented by the Host. The transport captures the caller
/// SID and hands a decoded request plus context to the policy/JEA pipeline.
/// </summary>
public interface IToolCallDispatcher
{
    Task<ToolCallResult> DispatchAsync(ToolCallRequest request, CallContext context, ElicitationChannel elicitation, CancellationToken ct);
}

/// <summary>Everything the broker must show a human (or an approver) to decide one call.</summary>
public sealed record ElicitationContext(string CorrelationId, string ToolId, string CallerSid, string ParamHash);

/// <summary>
/// Requests a human decision for one call and awaits it. The delegate is supplied by the
/// transport: in same-pipe mode it round-trips over the caller's pipe; in distinct-approver
/// mode it routes through the ElicitationRouter to a separate approval pipe.
/// </summary>
public sealed class ElicitationChannel
{
    private readonly Func<ElicitationContext, CancellationToken, Task<ElicitationReply>> _ask;

    public ElicitationChannel(Func<ElicitationContext, CancellationToken, Task<ElicitationReply>> ask) => _ask = ask;

    public Task<ElicitationReply> RequestAsync(ElicitationContext ctx, CancellationToken ct) => _ask(ctx, ct);
}

public sealed record ElicitationReply(
    string CorrelationId, string ParamHash, bool Approved, string DecidedBySid, string ToolId = "");

public sealed record PendingElicitation(
    string CorrelationId, string ToolId, string CallerSid, string ParamHash,
    DateTimeOffset ExpiresUtc, TaskCompletionSource<ElicitationReply> Tcs);

/// <summary>
/// Shared registry that decouples the caller's pipe from the approver's pipe. A dispatch
/// waiting on approval registers a pending entry here; connected approvers (on the separate
/// approval pipe) are notified and resolve it. This is what makes a distinct approver —
/// not the caller — able to answer an elicitation.
/// </summary>
public sealed class ElicitationRouter
{
    private readonly ConcurrentDictionary<string, PendingElicitation> _pending = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<Guid, Func<PendingElicitation, Task>> _approverSinks = new();
    private readonly object _pendingLock = new();
    private readonly ILogger<ElicitationRouter> _logger;

    public ElicitationRouter(ILogger<ElicitationRouter> logger) => _logger = logger;

    public bool HasApprovers => !_approverSinks.IsEmpty;

    public async Task<ElicitationReply> RequestAsync(ElicitationContext ctx, TimeSpan ttl, CancellationToken ct)
    {
        var tcs = new TaskCompletionSource<ElicitationReply>(TaskCreationOptions.RunContinuationsAsynchronously);
        var pe = new PendingElicitation(
            ctx.CorrelationId, ctx.ToolId, ctx.CallerSid, ctx.ParamHash,
            DateTimeOffset.UtcNow.Add(ttl), tcs);
        lock (_pendingLock)
            _pending[ctx.CorrelationId] = pe;

        try
        {
            if (_approverSinks.IsEmpty)
                _logger.LogWarning("No approver connected; elicitation {Corr} will wait and likely time out",
                    ctx.CorrelationId);

            foreach (var sink in _approverSinks.Values)
                _ = NotifySafelyAsync(sink, pe);

            using var ttlCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            ttlCts.CancelAfter(ttl);
            return await tcs.Task.WaitAsync(ttlCts.Token);
        }
        finally
        {
            lock (_pendingLock)
                _pending.TryRemove(ctx.CorrelationId, out _);
        }
    }

    public bool TryResolve(string correlationId, ElicitationReply reply)
    {
        lock (_pendingLock)
        {
            if (!_pending.TryGetValue(correlationId, out var pe) ||
                DateTimeOffset.UtcNow >= pe.ExpiresUtc ||
                !string.Equals(reply.CorrelationId, pe.CorrelationId, StringComparison.Ordinal) ||
                !string.Equals(reply.ToolId, pe.ToolId, StringComparison.Ordinal) ||
                !string.Equals(reply.ParamHash, pe.ParamHash, StringComparison.Ordinal))
                return false;

            _pending.TryRemove(correlationId, out _);
            return pe.Tcs.TrySetResult(reply);
        }
    }

    private async Task NotifySafelyAsync(Func<PendingElicitation, Task> sink, PendingElicitation pe)
    {
        try { await sink(pe); }
        catch (Exception ex) { _logger.LogDebug(ex, "Approver notify failed for {Corr}", pe.CorrelationId); }
    }

    /// <summary>An approver connection registers a sink and receives the current backlog.</summary>
    public IDisposable RegisterApprover(Func<PendingElicitation, Task> sink, out IReadOnlyCollection<PendingElicitation> backlog)
    {
        var id = Guid.NewGuid();
        _approverSinks[id] = sink;
        backlog = _pending.Values.ToArray();
        return new Registration(() => _approverSinks.TryRemove(id, out _));
    }

    private sealed class Registration : IDisposable
    {
        private readonly Action _dispose;
        public Registration(Action dispose) => _dispose = dispose;
        public void Dispose() => _dispose();
    }
}

/// <summary>
/// Validation of the principals a pipe ACL may name. Pure string logic, so it is enforced and
/// tested identically on every platform. A pipe client must be an explicitly provisioned user or
/// group: the broad well-known principals (and the broad domain groups) are refused outright,
/// because "never use Everyone" written in documentation is not a control.
/// </summary>
internal static class PipePrincipals
{
    private static readonly System.Text.RegularExpressions.Regex SidSyntax =
        new(@"^S-1-\d+(-\d+)+$", System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    private static readonly HashSet<string> TooBroad = new(StringComparer.OrdinalIgnoreCase)
    {
        "S-1-1-0",        // Everyone
        "S-1-2-0",        // Local
        "S-1-5-2",        // Network
        "S-1-5-4",        // Interactive
        "S-1-5-7",        // Anonymous
        "S-1-5-11",       // Authenticated Users
        "S-1-5-15",       // This Organization
        "S-1-5-32-545",   // BUILTIN\Users
        "S-1-5-32-546"    // BUILTIN\Guests
    };

    // Domain Users, Domain Guests, Domain Computers: RIDs of the broad per-domain groups.
    private static readonly string[] BroadDomainRids = { "-513", "-514", "-515" };

    public static void Validate(IReadOnlyCollection<string> sids)
    {
        if (sids.Count == 0)
            throw new InvalidOperationException("No allowed SIDs supplied — refusing to open an unrestricted pipe.");

        foreach (var sid in sids)
        {
            if (string.IsNullOrWhiteSpace(sid) || !SidSyntax.IsMatch(sid))
                throw new InvalidOperationException("A configured pipe SID is not a valid SID string.");

            if (TooBroad.Contains(sid) ||
                (sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) &&
                 BroadDomainRids.Any(rid => sid.EndsWith(rid, StringComparison.Ordinal))))
                throw new InvalidOperationException($"Pipe SID {sid} is too broad to be a pipe client.");
        }
    }
}

/// <summary>
/// Builds an allowlist-only ACL for the pipe. No Everyone / Authenticated Users:
/// a caller must be an explicitly provisioned SID, plus the service's own identity.
/// </summary>
public sealed class PipeSecurityFactory
{
    private readonly IConfiguration _config;
    private readonly ILogger<PipeSecurityFactory> _logger;

    public PipeSecurityFactory(IConfiguration config, ILogger<PipeSecurityFactory> logger)
    {
        _config = config;
        _logger = logger;
    }

    public PipeSecurity Build()
        => BuildFor(_config.GetSection("Pipe:AllowedSids").Get<string[]>() ?? Array.Empty<string>());

    /// <summary>Builds an allowlist-only ACL for the given caller SIDs plus the service identity.</summary>
    public PipeSecurity BuildFor(IReadOnlyCollection<string> sids)
    {
        PipePrincipals.Validate(sids);

        var security = new PipeSecurity();
        foreach (var sidString in sids)
        {
            var sid = new SecurityIdentifier(sidString);
            security.AddAccessRule(new PipeAccessRule(sid, PipeAccessRights.ReadWrite, AccessControlType.Allow));
            _logger.LogInformation("Pipe ACL grants ReadWrite to {Sid}", sidString);
        }

        var selfSid = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("Cannot resolve current identity SID.");
        security.AddAccessRule(new PipeAccessRule(selfSid, PipeAccessRights.FullControl, AccessControlType.Allow));

        return security;
    }
}

/// <summary>
/// Length-prefixed JSON framing. uint32 big-endian length, payload capped at 1 MiB.
/// An over-cap declared length is rejected before any buffer is allocated.
/// </summary>
public static class McpFraming
{
    public const int MaxPayloadBytes = 1 * 1024 * 1024;

    /// <summary>
    /// Reads one frame. The wait for the first byte uses <paramref name="idle"/> only (a
    /// connection may sit idle between calls, or while an elicitation reply is outstanding,
    /// without being closed). Once a frame has started, <paramref name="partialTimeout"/>
    /// bounds completion so a half-sent frame cannot hold a slot open.
    /// </summary>
    public static async Task<string?> ReadFrameAsync(Stream stream, TimeSpan partialTimeout, CancellationToken idle)
    {
        var lenBuf = new byte[4];

        // First byte: block indefinitely (subject only to idle/service cancellation).
        int first = await stream.ReadAsync(lenBuf.AsMemory(0, 1), idle);
        if (first == 0) return null;

        // A frame has now started; bound the rest.
        using var frameCts = CancellationTokenSource.CreateLinkedTokenSource(idle);
        frameCts.CancelAfter(partialTimeout);
        var token = frameCts.Token;

        if (!await ReadExactAsync(stream, lenBuf.AsMemory(1, 3), token))
            throw new InvalidDataException("Stream closed mid-length-prefix.");

        uint declared = BinaryPrimitives.ReadUInt32BigEndian(lenBuf);
        if (declared == 0 || declared > MaxPayloadBytes)
            throw new InvalidDataException($"Frame length {declared} out of bounds (max {MaxPayloadBytes}).");

        var payload = new byte[declared];
        if (!await ReadExactAsync(stream, payload.AsMemory(), token))
            throw new InvalidDataException("Stream closed mid-frame.");

        return Encoding.UTF8.GetString(payload);
    }

    public static async Task WriteFrameAsync(Stream stream, string json, CancellationToken ct)
    {
        var payload = Encoding.UTF8.GetBytes(json);
        if (payload.Length > MaxPayloadBytes)
            throw new InvalidDataException("Response exceeds frame cap.");

        var lenBuf = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(lenBuf, (uint)payload.Length);
        await stream.WriteAsync(lenBuf, ct);
        await stream.WriteAsync(payload, ct);
        await stream.FlushAsync(ct);
    }

    private static async Task<bool> ReadExactAsync(Stream stream, Memory<byte> buffer, CancellationToken ct)
    {
        int offset = 0;
        while (offset < buffer.Length)
        {
            int read = await stream.ReadAsync(buffer[offset..], ct);
            if (read == 0) return false;
            offset += read;
        }
        return true;
    }
}

/// <summary>
/// Multi-instance named pipe listener. Fixed slot count bounds resource use.
/// Each connection gets a per-frame timeout so a stalled client cannot hold a slot, a bounded
/// number of in-flight requests, and a bounded tolerance for malformed messages.
/// </summary>
public sealed class NamedPipeServer
{
    private readonly PipeSecurityFactory _securityFactory;
    private readonly IToolCallDispatcher _dispatcher;
    private readonly ElicitationRouter _router;
    private readonly IConfiguration _config;
    private readonly ILogger<NamedPipeServer> _logger;

    public NamedPipeServer(
        PipeSecurityFactory securityFactory,
        IToolCallDispatcher dispatcher,
        ElicitationRouter router,
        IConfiguration config,
        ILogger<NamedPipeServer> logger)
    {
        _securityFactory = securityFactory;
        _dispatcher = dispatcher;
        _router = router;
        _config = config;
        _logger = logger;
    }

    private string PipeName => _config["Pipe:Name"] ?? "McpBroker";
    private int MaxInstances => int.TryParse(_config["Pipe:MaxInstances"], out var n) ? n : 8;
    private int FrameTimeoutSeconds => int.TryParse(_config["Pipe:FrameTimeoutSeconds"], out var n) ? n : 5;
    private int MaxInFlightPerConnection => PositiveInt("Pipe:MaxInFlightPerConnection", 16);
    private int MaxMalformedRequests => PositiveInt("Pipe:MaxMalformedRequests", 5);
    private int ElicitationTtlSeconds => int.TryParse(_config["Elicitation:TtlSeconds"], out var n) ? n : 120;
    private bool RequireDistinctApprover =>
        bool.TryParse(_config["Elicitation:RequireDistinctApprover"], out var b) && b;

    private int PositiveInt(string key, int fallback) =>
        int.TryParse(_config[key], out var n) && n > 0 ? n : fallback;

    public async Task RunAsync(CancellationToken ct)
    {
        var security = _securityFactory.Build();
        _logger.LogInformation("Opening pipe {Pipe} with {Slots} slots", PipeName, MaxInstances);

        var slots = Enumerable.Range(0, MaxInstances).Select(i => AcceptLoopAsync(i, security, ct));
        await Task.WhenAll(slots);
    }

    private async Task AcceptLoopAsync(int slot, PipeSecurity security, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream stream;
            try
            {
                stream = NamedPipeServerStreamAcl.Create(
                    PipeName, PipeDirection.InOut, MaxInstances,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous,
                    inBufferSize: 0, outBufferSize: 0, pipeSecurity: security);
            }
            catch (IOException ex)
            {
                _logger.LogError(ex, "Slot {Slot}: cannot create pipe instance", slot);
                await Task.Delay(1000, ct);
                continue;
            }

            try
            {
                await stream.WaitForConnectionAsync(ct);

                // A connection whose identity cannot be established is dropped, never served.
                string callerSid;
                try
                {
                    callerSid = RequireCallerSid(CaptureCallerSid(stream));
                }
                catch (Exception ex) when (ex is InvalidOperationException or IOException or UnauthorizedAccessException)
                {
                    _logger.LogWarning(ex, "Slot {Slot}: caller identity could not be established; connection refused", slot);
                    continue;
                }

                _logger.LogInformation("Slot {Slot}: client connected SID={Sid}", slot, callerSid);
                await ServeAsync(stream, () => stream.IsConnected, callerSid, ct);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Slot {Slot}: connection error", slot);
            }
            finally
            {
                await stream.DisposeAsync();
            }
        }
    }

    /// <summary>
    /// The identity every authorization decision hangs off must exist. A missing or blank
    /// impersonated SID is an error, not an anonymous caller.
    /// </summary>
    internal static string RequireCallerSid(string? sid) =>
        string.IsNullOrWhiteSpace(sid)
            ? throw new InvalidOperationException("The connecting client's SID could not be determined.")
            : sid;

    private static string CaptureCallerSid(NamedPipeServerStream stream)
    {
        string sid = string.Empty;
        stream.RunAsClient(() => sid = WindowsIdentity.GetCurrent().User?.Value ?? string.Empty);
        return sid;
    }

    internal async Task ServeAsync(Stream stream, Func<bool> isConnected, string callerSid, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(callerSid))
        {
            _logger.LogWarning("Connection without a caller identity refused");
            return;
        }

        // Reads and dispatches are decoupled. A single reader loop demuxes frames: tool calls
        // start a background dispatch, elicitation replies resolve the waiting dispatch's TCS.
        // The reader never blocks on dispatch, so an in-flight elicitation does not deadlock.
        var pending = new ConcurrentDictionary<string, TaskCompletionSource<ElicitationReply>>();
        var writeLock = new SemaphoreSlim(1, 1);
        var inflight = new ConcurrentDictionary<Task, byte>();
        int malformed = 0;
        int maxInFlight = MaxInFlightPerConnection;
        int maxMalformed = MaxMalformedRequests;

        async Task WriteFrameLocked(string json)
        {
            await writeLock.WaitAsync(ct);
            try { await McpFraming.WriteFrameAsync(stream, json, ct); }
            finally { writeLock.Release(); }
        }

        // Same-pipe elicitation is retained for compatibility with read-only test
        // dispatchers; ConsentEngine rejects self-approval for mutating tools.
        async Task<ElicitationReply> SamePipeAsync(ElicitationContext ectx, CancellationToken token)
        {
            var tcs = new TaskCompletionSource<ElicitationReply>(TaskCreationOptions.RunContinuationsAsynchronously);
            pending[ectx.CorrelationId] = tcs;
            try
            {
                await WriteFrameLocked(JsonSerializer.Serialize(new
                {
                    type = "elicitation/request",
                    correlationId = ectx.CorrelationId,
                    paramHash = ectx.ParamHash
                }));

                using var ttl = CancellationTokenSource.CreateLinkedTokenSource(token);
                ttl.CancelAfter(TimeSpan.FromSeconds(ElicitationTtlSeconds));
                return await tcs.Task.WaitAsync(ttl.Token);
            }
            finally
            {
                pending.TryRemove(ectx.CorrelationId, out _);
            }
        }

        // Distinct-approver mode: route to the shared router, answered on the approval pipe.
        var elicitation = new ElicitationChannel((ectx, token) =>
            RequireDistinctApprover
                ? _router.RequestAsync(ectx, TimeSpan.FromSeconds(ElicitationTtlSeconds), token)
                : SamePipeAsync(ectx, token));

        async Task RefuseAsync(string reason)
        {
            var correlationId = Guid.NewGuid().ToString("N");
            _logger.LogWarning("Refused message from SID={Sid} ({Corr}): {Reason}", callerSid, correlationId, reason);
            await WriteFrameLocked(RejectionJson(correlationId, reason));
        }

        try
        {
            while (!ct.IsCancellationRequested && isConnected())
            {
                string? frame;
                try
                {
                    frame = await McpFraming.ReadFrameAsync(
                        stream, TimeSpan.FromSeconds(FrameTimeoutSeconds), ct);
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    _logger.LogWarning("Partial-frame timeout, closing connection SID={Sid}", callerSid);
                    break;
                }
                catch (InvalidDataException ex)
                {
                    _logger.LogWarning(ex, "Protocol violation, closing connection SID={Sid}", callerSid);
                    break;
                }

                if (frame is null) break;

                ToolCallRequest? request = null;
                ElicitationReply? reply = null;
                try
                {
                    (request, reply) = ParseMessage(frame, callerSid);
                }
                catch (Exception ex) when (ex is JsonException or InvalidDataException
                                              or InvalidOperationException or KeyNotFoundException or FormatException)
                {
                    // Framing is intact, only the payload is unusable: refuse it and keep the
                    // session, but not forever.
                    _logger.LogWarning(ex, "Malformed message from SID={Sid}", callerSid);
                    await RefuseAsync("malformed-request");
                    if (++malformed >= maxMalformed)
                    {
                        _logger.LogWarning("Too many malformed messages, closing connection SID={Sid}", callerSid);
                        break;
                    }
                    continue;
                }

                if (reply is not null)
                {
                    if (pending.TryGetValue(reply.CorrelationId, out var tcs))
                        tcs.TrySetResult(reply);
                    continue;
                }

                if (inflight.Count >= maxInFlight)
                {
                    await RefuseAsync("too-many-inflight-requests");
                    continue;
                }

                var context = CallContext.New(callerSid, request!.ToolId);
                var dispatchTask = DispatchAndRespondAsync(request, context, elicitation, WriteFrameLocked, ct);
                inflight[dispatchTask] = 0;
                _ = dispatchTask.ContinueWith(t => inflight.TryRemove(t, out _), TaskScheduler.Default);
            }
        }
        finally
        {
            // Unblock any dispatch still waiting on an elicitation reply, then drain briefly.
            foreach (var kvp in pending) kvp.Value.TrySetCanceled();
            try { await Task.WhenAll(inflight.Keys).WaitAsync(TimeSpan.FromSeconds(5)); }
            catch (Exception ex) { _logger.LogDebug(ex, "Drain of in-flight dispatches ended early"); }
            writeLock.Dispose();
        }
    }

    private async Task DispatchAndRespondAsync(
        ToolCallRequest request, CallContext context, ElicitationChannel elicitation,
        Func<string, Task> writeFrame, CancellationToken ct)
    {
        try
        {
            var result = await _dispatcher.DispatchAsync(request, context, elicitation, ct);
            var envelope = JsonSerializer.Serialize(new
            {
                type = "tools/result",
                correlationId = context.CorrelationId,
                success = result.Success,
                rejectReason = result.RejectReason,
                payload = result.PayloadJson
            });

            // An answer that cannot fit in one frame is reported as such, not as an internal error.
            if (Encoding.UTF8.GetByteCount(envelope) > McpFraming.MaxPayloadBytes)
            {
                _logger.LogWarning("Result for {Tool} ({Corr}) exceeds the frame cap", context.ToolId, context.CorrelationId);
                envelope = RejectionJson(context.CorrelationId, "response-too-large");
            }

            await writeFrame(envelope);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Dispatch failed for {Tool} ({Corr})", context.ToolId, context.CorrelationId);
            try { await writeFrame(RejectionJson(context.CorrelationId, "internal-error")); }
            catch { /* connection likely gone */ }
        }
    }

    private static string RejectionJson(string correlationId, string reason) =>
        JsonSerializer.Serialize(new
        {
            type = "tools/result",
            correlationId,
            success = false,
            rejectReason = reason,
            payload = (string?)null
        });

    /// <summary>
    /// Strict message parse. Exactly two message types exist ("tools/call", which is also the
    /// default when "type" is absent, and "elicitation/reply"); anything else is malformed rather
    /// than being guessed at. Throws on any structural problem.
    /// </summary>
    internal static (ToolCallRequest? request, ElicitationReply? reply) ParseMessage(string frame, string callerSid)
    {
        using var doc = JsonDocument.Parse(frame);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("Message is not a JSON object.");

        var kind = "tools/call";
        if (root.TryGetProperty("type", out var t))
        {
            if (t.ValueKind != JsonValueKind.String)
                throw new InvalidDataException("Message type is not a string.");
            kind = t.GetString()!;
        }

        return kind switch
        {
            "elicitation/reply" => (null, ParseElicitationReply(root, callerSid)),
            "tools/call" => (ParseToolCall(root), null),
            _ => throw new InvalidDataException("Unknown message type.")
        };
    }

    private static string OptionalString(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var e)) return string.Empty;
        return e.ValueKind == JsonValueKind.String
            ? e.GetString() ?? string.Empty
            : throw new InvalidDataException($"'{name}' is not a string.");
    }

    private static ElicitationReply ParseElicitationReply(JsonElement root, string callerSid)
    {
        var correlationId = OptionalString(root, "correlationId");
        var paramHash = OptionalString(root, "paramHash");
        var toolId = OptionalString(root, "toolId");

        // Only the JSON literal true approves. "true", 1, null and every other shape are not approval.
        var approved = root.TryGetProperty("approved", out var a) && a.ValueKind == JsonValueKind.True;

        // SECURITY: the approver identity on this path MUST be the connection's own
        // OS-impersonated callerSid, captured via RunAsClient at connect time — never a
        // client-supplied field. A prior version read an optional "decidedBySid" from the
        // reply body here, which let a caller forge an arbitrary approver identity in its
        // own JSON and defeat ConsentEngine's self-approval-forbidden check entirely (send
        // approved:true with any decidedBySid != its own SID). Any JSON field is untrusted
        // input; it is never used for an authorization decision. The distinct-approver path
        // (ApprovalPipeServer, separate pipe) is unaffected — it already derives its approver
        // identity the same way, from that pipe's own impersonation, not from the message body.
        return new ElicitationReply(correlationId, paramHash, approved, callerSid, toolId);
    }

    private static ToolCallRequest ParseToolCall(JsonElement root)
    {
        if (!root.TryGetProperty("toolId", out var id) || id.ValueKind != JsonValueKind.String ||
            string.IsNullOrWhiteSpace(id.GetString()))
            throw new InvalidDataException("tools/call missing toolId.");

        var parameters = new Dictionary<string, string>(StringComparer.Ordinal);
        if (root.TryGetProperty("parameters", out var p) && p.ValueKind != JsonValueKind.Null)
        {
            if (p.ValueKind != JsonValueKind.Object)
                throw new InvalidDataException("'parameters' is not an object.");

            foreach (var prop in p.EnumerateObject())
            {
                // Two values for one name would let different components pick different winners.
                if (!parameters.TryAdd(prop.Name, ToWireString(prop.Value)))
                    throw new InvalidDataException("Duplicate parameter name.");
            }
        }

        return new ToolCallRequest { ToolId = id.GetString()!, Parameters = parameters };
    }

    /// <summary>
    /// Canonical wire text for a scalar. JSON true/false become "true"/"false" (not "True"/"False"),
    /// numbers keep their exact text (so an integer parameter can reject "1.5" or "1e1"), and
    /// objects, arrays and null are never valid parameter values.
    /// </summary>
    private static string ToWireString(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String => value.GetString()!,
        JsonValueKind.Number => value.GetRawText(),
        JsonValueKind.True => "true",
        JsonValueKind.False => "false",
        _ => throw new InvalidDataException("Parameter values must be strings, numbers or booleans.")
    };
}

/// <summary>
/// Separate, ACL-restricted pipe where authorized approvers answer elicitations for
/// destructive calls. Only SIDs in Elicitation:ApproverSids can connect. An approver
/// receives pending requests (plus any backlog on connect) and sends replies; the reply's
/// approver identity is the pipe's caller SID, so a caller cannot self-approve.
/// </summary>
public sealed class ApprovalPipeServer
{
    private readonly PipeSecurityFactory _securityFactory;
    private readonly ElicitationRouter _router;
    private readonly IConfiguration _config;
    private readonly ILogger<ApprovalPipeServer> _logger;
    private readonly HashSet<string> _approverSids;

    public ApprovalPipeServer(
        PipeSecurityFactory securityFactory, ElicitationRouter router,
        IConfiguration config, ILogger<ApprovalPipeServer> logger)
    {
        _securityFactory = securityFactory;
        _router = router;
        _config = config;
        _logger = logger;
        _approverSids = new HashSet<string>(
            config.GetSection("Elicitation:ApproverSids").Get<string[]>() ?? Array.Empty<string>(),
            StringComparer.OrdinalIgnoreCase);
    }

    private string PipeName => _config["Elicitation:ApprovalPipeName"] ?? "McpBroker.Approvals";
    private int MaxInstances => int.TryParse(_config["Elicitation:ApprovalPipeInstances"], out var n) ? n : 4;

    public async Task RunAsync(CancellationToken ct)
    {
        var sids = _approverSids.ToArray();
        if (sids.Length == 0)
        {
            _logger.LogError("Elicitation:ApproverSids is empty; approval pipe not started (distinct-approver calls will fail closed)");
            return;
        }

        var security = _securityFactory.BuildFor(sids);
        _logger.LogInformation("Opening approval pipe {Pipe} with {Slots} slots", PipeName, MaxInstances);

        var slots = Enumerable.Range(0, MaxInstances).Select(i => AcceptLoopAsync(i, security, ct));
        await Task.WhenAll(slots);
    }

    private async Task AcceptLoopAsync(int slot, PipeSecurity security, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream stream;
            try
            {
                stream = NamedPipeServerStreamAcl.Create(
                    PipeName, PipeDirection.InOut, MaxInstances,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous,
                    inBufferSize: 0, outBufferSize: 0, pipeSecurity: security);
            }
            catch (IOException ex)
            {
                _logger.LogError(ex, "Approval slot {Slot}: cannot create pipe instance", slot);
                await Task.Delay(1000, ct);
                continue;
            }

            try
            {
                await stream.WaitForConnectionAsync(ct);

                string approverSid;
                try
                {
                    approverSid = NamedPipeServer.RequireCallerSid(CaptureSid(stream));
                }
                catch (Exception ex) when (ex is InvalidOperationException or IOException or UnauthorizedAccessException)
                {
                    _logger.LogWarning(ex, "Approval slot {Slot}: approver identity could not be established; connection refused", slot);
                    continue;
                }

                _logger.LogInformation("Approval slot {Slot}: approver connected SID={Sid}", slot, approverSid);
                await ServeApproverAsync(stream, () => stream.IsConnected, approverSid, ct);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Approval slot {Slot}: connection error", slot);
            }
            finally
            {
                await stream.DisposeAsync();
            }
        }
    }

    private static string CaptureSid(NamedPipeServerStream stream)
    {
        string sid = string.Empty;
        stream.RunAsClient(() => sid = WindowsIdentity.GetCurrent().User?.Value ?? string.Empty);
        return sid;
    }

    internal async Task ServeApproverAsync(Stream stream, Func<bool> isConnected, string approverSid, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(approverSid))
        {
            _logger.LogWarning("Approver connection without an identity refused");
            return;
        }

        var writeLock = new SemaphoreSlim(1, 1);

        async Task Notify(PendingElicitation pe)
        {
            var json = JsonSerializer.Serialize(new
            {
                type = "approval/request",
                correlationId = pe.CorrelationId,
                toolId = pe.ToolId,
                callerSid = pe.CallerSid,
                paramHash = pe.ParamHash,
                expiresUtc = pe.ExpiresUtc
            });
            await writeLock.WaitAsync(ct);
            try { await McpFraming.WriteFrameAsync(stream, json, ct); }
            finally { writeLock.Release(); }
        }

        using var registration = _router.RegisterApprover(Notify, out var backlog);
        foreach (var pe in backlog) await Notify(pe);

        try
        {
            while (!ct.IsCancellationRequested && isConnected())
            {
                string? frame;
                try
                {
                    frame = await McpFraming.ReadFrameAsync(stream, TimeSpan.FromSeconds(30), ct);
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested) { continue; }
                catch (InvalidDataException ex)
                {
                    _logger.LogWarning(ex, "Approver protocol violation SID={Sid}", approverSid);
                    break;
                }

                if (frame is null) break;

                string correlationId, paramHash, toolId;
                bool approved;
                try
                {
                    using var doc = JsonDocument.Parse(frame);
                    var root = doc.RootElement;
                    if (root.ValueKind != JsonValueKind.Object)
                        throw new InvalidDataException("Approval message is not a JSON object.");

                    correlationId = ApprovalString(root, "correlationId");
                    paramHash = ApprovalString(root, "paramHash");
                    toolId = ApprovalString(root, "toolId");

                    // Only a literal true or false is a decision; any other shape is not an answer.
                    if (!root.TryGetProperty("approved", out var a) ||
                        (a.ValueKind != JsonValueKind.True && a.ValueKind != JsonValueKind.False))
                        throw new InvalidDataException("'approved' must be a JSON boolean.");
                    approved = a.ValueKind == JsonValueKind.True;
                }
                catch (Exception ex) when (ex is JsonException or InvalidDataException)
                {
                    _logger.LogWarning(ex, "Malformed approver message, closing session SID={Sid}", approverSid);
                    break;
                }

                // Defense in depth behind the pipe ACL: the ACL also admits the service's own
                // identity, which is not an approver. A reply from any SID outside the approver
                // list is ignored and must not consume the pending request.
                if (!_approverSids.Contains(approverSid))
                {
                    _logger.LogWarning("Reply from SID {Sid} ignored: not an authorized approver", approverSid);
                    continue;
                }

                // Approver identity is the pipe's caller SID — not client-supplied — so the
                // separation-of-duties check in ConsentEngine cannot be forged by the caller.
                var reply = new ElicitationReply(correlationId, paramHash, approved, approverSid, toolId);
                if (!_router.TryResolve(correlationId, reply))
                    _logger.LogDebug("Approval for {Corr} had no matching pending request (expired or mismatched?)", correlationId);
            }
        }
        finally
        {
            writeLock.Dispose();
        }
    }

    private static string ApprovalString(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var e)) return string.Empty;
        return e.ValueKind == JsonValueKind.String
            ? e.GetString() ?? string.Empty
            : throw new InvalidDataException($"'{name}' is not a string.");
    }
}
