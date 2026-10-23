using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Broker.Core;
using Broker.Registry;
using Microsoft.Extensions.Logging;

[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("Broker.Tests")]

namespace Broker.Policy;

/// <summary>
/// The single definition of what each manifest parameter type means. The validator and the
/// argv builder both go through this class, so a value can never pass validation under one
/// parser and then be converted by a different one. Parsing is culture-invariant, ASCII-only
/// and canonical: no whitespace, no thousands separators, no exponent form for integers, no
/// "+" sign, and booleans are exactly "true" or "false".
/// </summary>
public static class ParameterTypes
{
    public static bool IsSupported(string? type) => type is "string" or "enum" or "int" or "bool";

    public static bool TryParseInt(string raw, out int value)
    {
        value = 0;
        if (string.IsNullOrEmpty(raw) || raw.Length > 11) return false;

        int i = raw[0] == '-' ? 1 : 0;
        if (i == raw.Length) return false;
        for (int j = i; j < raw.Length; j++)
            if (raw[j] < '0' || raw[j] > '9') return false;

        return int.TryParse(raw, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out value);
    }

    public static bool TryParseBool(string raw, out bool value)
    {
        switch (raw)
        {
            case "true": value = true; return true;
            case "false": value = false; return true;
            default: value = false; return false;
        }
    }

    public static bool TryParseFiniteNumber(string raw, out double value)
    {
        const NumberStyles styles = NumberStyles.AllowLeadingSign | NumberStyles.AllowDecimalPoint | NumberStyles.AllowExponent;
        return double.TryParse(raw, styles, CultureInfo.InvariantCulture, out value) && double.IsFinite(value);
    }

    /// <summary>Converts a raw wire value into the CLR value passed to PowerShell, or fails.</summary>
    public static bool TryConvert(string? type, string raw, out object value)
    {
        value = raw;
        switch (type)
        {
            case "string":
            case "enum":
                return true;
            case "int":
                if (!TryParseInt(raw, out var i)) return false;
                value = i;
                return true;
            case "bool":
                if (!TryParseBool(raw, out var b)) return false;
                value = b;
                return true;
            default:
                return false;
        }
    }
}

/// <summary>
/// Validates caller parameters against the per-parameter allowlist in the manifest.
/// Broker-side defense in depth; JEA re-validates independently inside the session.
/// </summary>
public sealed class ParameterValidator
{
    public PolicyDecision Validate(ToolManifest tool, IReadOnlyDictionary<string, string> supplied)
    {
        // reject unknown parameters outright. The name is attacker-chosen, so it is echoed back (and
        // so reaches logs and the audit trail) only when it is a plain identifier.
        var known = tool.Parameters.Select(p => p.Name).ToHashSet(StringComparer.Ordinal);
        foreach (var key in supplied.Keys)
            if (!known.Contains(key))
                return PolicyDecision.Deny($"unknown-parameter:{(IsPlainIdentifier(key) ? key : "invalid-name")}");

        // A scope that names no parameter would never be applied; refuse the tool rather than
        // run it believing it is scoped.
        foreach (var scoped in tool.ResourceAllowlist.Keys)
            if (!known.Contains(scoped))
                return PolicyDecision.Deny($"resource-scope-unknown-parameter:{scoped}");

        foreach (var p in tool.Parameters)
        {
            var present = supplied.TryGetValue(p.Name, out var value);
            if (!present)
            {
                if (p.Required) return PolicyDecision.Deny($"missing-required-parameter:{p.Name}");

                // A scoped parameter that is simply left out would skip its scope check entirely.
                if (tool.ResourceAllowlist.ContainsKey(p.Name))
                    return PolicyDecision.Deny($"resource-scope-requires-parameter:{p.Name}");
                continue;
            }

            var reason = CheckOne(p, value);
            if (reason is not null) return PolicyDecision.Deny(reason);

            if (tool.ResourceAllowlist.TryGetValue(p.Name, out var allowedResources) &&
                !allowedResources.Contains(value!, StringComparer.OrdinalIgnoreCase))
                return PolicyDecision.Deny($"resource-not-allowlisted:{p.Name}");
        }

        return PolicyDecision.Allow();
    }

    private static bool IsPlainIdentifier(string name) =>
        name.Length is >= 1 and <= 64 && name.All(c => c is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9') or '_' or '.' or '-');

    private static string? CheckOne(ToolParameter p, string? value)
    {
        if (value is null) return $"parameter-null:{p.Name}";

        // Control characters are never legitimate in any shipped parameter, and .NET's `$` anchor
        // matches before a trailing "\n", so a regex-valid value could otherwise smuggle one through.
        // Format characters (bidi overrides, zero-width characters, byte-order marks) and line or
        // paragraph separators are refused too: they let a value read differently to the human
        // approving it than to the machine running it. Rejected before any pattern is consulted.
        foreach (var ch in value)
        {
            var category = char.GetUnicodeCategory(ch);
            if (category is UnicodeCategory.Control or UnicodeCategory.Format
                or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator)
                return $"parameter-control-character:{p.Name}";
        }

        if (!ParameterTypes.IsSupported(p.Type)) return $"parameter-type-unsupported:{p.Name}";

        var a = p.Allowlist;

        if (a.MaxLength is { } max && value.Length > max)
            return $"parameter-too-long:{p.Name}";

        // Type conformity uses the same parser the argv builder will use.
        int intValue = 0;
        if (p.Type == "int" && !ParameterTypes.TryParseInt(value, out intValue))
            return $"parameter-not-integer:{p.Name}";
        if (p.Type == "bool" && !ParameterTypes.TryParseBool(value, out _))
            return $"parameter-not-boolean:{p.Name}";

        if (a.EnumValues is { Count: > 0 } set && !set.Contains(value, StringComparer.Ordinal))
            return $"parameter-not-in-enum:{p.Name}";

        if (a.RegexPattern is { } pattern &&
            !Regex.IsMatch(value, pattern, RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100)))
            return $"parameter-pattern-mismatch:{p.Name}";

        if (a.Range is { } range)
        {
            double num;
            if (p.Type == "int") num = intValue;
            else if (!ParameterTypes.TryParseFiniteNumber(value, out num)) return $"parameter-not-numeric:{p.Name}";
            if (num < range.Min || num > range.Max) return $"parameter-out-of-range:{p.Name}";
        }

        // schema guarantees at least one constraint; if somehow none, fail closed
        bool hasConstraint = a.MaxLength is not null || a.EnumValues is { Count: > 0 }
            || a.RegexPattern is not null || a.Range is not null;
        return hasConstraint ? null : $"parameter-has-no-allowlist:{p.Name}";
    }
}

/// <summary>
/// Hard gate: if a tool's output may contain untrusted external data AND the tool is
/// write/destructive, reject with no elicitation override. Prompt-injection defense.
/// </summary>
public sealed class UntrustedSourceGate
{
    public PolicyDecision Evaluate(ToolManifest tool)
    {
        bool touchesUntrusted = tool.UntrustedInputSources.Count > 0;
        bool mutates = tool.RiskTier is RiskTier.Write or RiskTier.Destructive;

        if (touchesUntrusted && mutates)
            return PolicyDecision.Deny("untrusted-source-cannot-mutate");

        return PolicyDecision.Allow();
    }
}

/// <summary>
/// Sliding-window rate limiter: a per-caller budget, a separate per-caller destructive budget,
/// and a global budget across all callers. The global budget supplements the per-caller ones, so
/// many individually-compliant callers still cannot exceed what the host can absorb. A denied
/// call consumes no budget. Idle caller state is pruned so memory does not grow without bound.
/// </summary>
public sealed class RateLimiter
{
    private static readonly TimeSpan CallWindow = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan DestructiveWindow = TimeSpan.FromHours(1);
    private static readonly TimeSpan PruneInterval = TimeSpan.FromMinutes(1);

    private readonly int _callsPerMinute;
    private readonly int _destructivePerHour;
    private readonly int _globalCallsPerMinute;
    private readonly TimeProvider _clock;
    private readonly object _lock = new();
    private readonly Dictionary<string, Queue<DateTimeOffset>> _all = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Queue<DateTimeOffset>> _destructive = new(StringComparer.Ordinal);
    private readonly Queue<DateTimeOffset> _global = new();
    private DateTimeOffset _lastPrune;

    /// <param name="globalCallsPerMinute">Total calls per minute across all callers; 0 or less disables only this limit.</param>
    public RateLimiter(int callsPerMinute = 60, int destructivePerHour = 10, int globalCallsPerMinute = 600,
        TimeProvider? clock = null)
    {
        _callsPerMinute = callsPerMinute;
        _destructivePerHour = destructivePerHour;
        _globalCallsPerMinute = globalCallsPerMinute;
        _clock = clock ?? TimeProvider.System;
        _lastPrune = _clock.GetUtcNow();
    }

    internal int TrackedCallerCount
    {
        get { lock (_lock) return _all.Count; }
    }

    public PolicyDecision Check(string callerSid, RiskTier tier)
    {
        if (string.IsNullOrWhiteSpace(callerSid))
            return PolicyDecision.Deny("caller-identity-missing");

        var now = _clock.GetUtcNow();
        lock (_lock)
        {
            PruneIfDue(now);

            var callerQueue = QueueFor(_all, callerSid);
            Trim(callerQueue, now, CallWindow);
            if (callerQueue.Count >= _callsPerMinute)
                return PolicyDecision.Deny("rate-limit-exceeded");

            if (_globalCallsPerMinute > 0)
            {
                Trim(_global, now, CallWindow);
                if (_global.Count >= _globalCallsPerMinute)
                    return PolicyDecision.Deny("global-rate-limit-exceeded");
            }

            Queue<DateTimeOffset>? destructiveQueue = null;
            if (tier is RiskTier.Destructive)
            {
                destructiveQueue = QueueFor(_destructive, callerSid);
                Trim(destructiveQueue, now, DestructiveWindow);
                if (destructiveQueue.Count >= _destructivePerHour)
                    return PolicyDecision.Deny("destructive-rate-limit-exceeded");
            }

            // Every budget has room: only now is any of them consumed.
            callerQueue.Enqueue(now);
            if (_globalCallsPerMinute > 0) _global.Enqueue(now);
            destructiveQueue?.Enqueue(now);
            return PolicyDecision.Allow();
        }
    }

    private static Queue<DateTimeOffset> QueueFor(Dictionary<string, Queue<DateTimeOffset>> map, string sid)
    {
        if (!map.TryGetValue(sid, out var q)) { q = new(); map[sid] = q; }
        return q;
    }

    private static void Trim(Queue<DateTimeOffset> q, DateTimeOffset now, TimeSpan window)
    {
        while (q.Count > 0 && now - q.Peek() > window) q.Dequeue();
    }

    private void PruneIfDue(DateTimeOffset now)
    {
        if (now - _lastPrune < PruneInterval) return;
        _lastPrune = now;
        Prune(_all, now, CallWindow);
        Prune(_destructive, now, DestructiveWindow);
    }

    private static void Prune(Dictionary<string, Queue<DateTimeOffset>> map, DateTimeOffset now, TimeSpan window)
    {
        foreach (var sid in map.Keys.ToArray())
        {
            Trim(map[sid], now, window);
            if (map[sid].Count == 0) map.Remove(sid);
        }
    }
}

/// <summary>
/// Builds the argument set for a JEA cmdlet invocation as a typed dictionary — never a
/// composed shell/command string. Refuses any parameter not backed by an allowlist entry and
/// converts values with <see cref="ParameterTypes"/>, the same definitions the validator uses.
/// Every refusal is an <see cref="InvalidOperationException"/> whose message never contains a
/// caller-supplied value, so it is safe to log and cannot leak into a client response.
/// </summary>
public sealed class ArgvBuilder
{
    public IReadOnlyDictionary<string, object> Build(ToolManifest tool, IReadOnlyDictionary<string, string> supplied)
    {
        var known = tool.Parameters.Select(p => p.Name).ToHashSet(StringComparer.Ordinal);
        if (supplied.Keys.Any(k => !known.Contains(k)))
            throw new InvalidOperationException("Refusing to build call: a parameter not defined for the tool was supplied.");

        var argv = new Dictionary<string, object>(StringComparer.Ordinal);

        foreach (var p in tool.Parameters)
        {
            bool hasConstraint = p.Allowlist.MaxLength is not null || p.Allowlist.EnumValues is { Count: > 0 }
                || p.Allowlist.RegexPattern is not null || p.Allowlist.Range is not null;
            if (!hasConstraint)
                throw new InvalidOperationException($"Refusing to build call: parameter {p.Name} has no allowlist.");

            if (!supplied.TryGetValue(p.Name, out var raw)) continue;

            if (raw is null || !ParameterTypes.TryConvert(p.Type, raw, out var converted))
                throw new InvalidOperationException(
                    $"Refusing to build call: parameter {p.Name} is not a valid '{p.Type}'.");

            argv[p.Name] = converted;
        }

        return argv;
    }
}

/// <summary>
/// What the scanner does when AMSI cannot give an answer (no amsi.dll, no registered provider,
/// scan error). Detected / blocked-by-admin content is denied in BOTH modes.
/// </summary>
public enum AmsiMode
{
    /// <summary>Default. AMSI trouble is logged and the call continues; AMSI is a supplementary signal.</summary>
    BestEffort = 0,
    /// <summary>AMSI trouble denies the call. Use only on hosts where an AMSI provider is guaranteed.</summary>
    Strict = 1
}

public static class AmsiOptions
{
    /// <summary>An unrecognized value must stop startup rather than silently select a mode.</summary>
    public static AmsiMode ParseMode(string? raw)
    {
        if (string.Equals(raw, "BestEffort", StringComparison.OrdinalIgnoreCase)) return AmsiMode.BestEffort;
        if (string.Equals(raw, "Strict", StringComparison.OrdinalIgnoreCase)) return AmsiMode.Strict;
        throw new InvalidOperationException("Configuration value 'Amsi:Mode' must be 'BestEffort' or 'Strict'.");
    }
}

/// <summary>Seam over amsi.dll so scanner behaviour is testable without a real AMSI provider.</summary>
internal interface IAmsiApi
{
    int Initialize(string appName, out IntPtr context);
    int OpenSession(IntPtr context, out IntPtr session);
    int Scan(IntPtr context, byte[] buffer, uint length, string contentName, IntPtr session, out int result);
    void CloseSession(IntPtr context, IntPtr session);
    void Uninitialize(IntPtr context);
}

internal sealed class NativeAmsiApi : IAmsiApi
{
    public int Initialize(string appName, out IntPtr context) => AmsiInitialize(appName, out context);
    public int OpenSession(IntPtr context, out IntPtr session) => AmsiOpenSession(context, out session);
    public int Scan(IntPtr context, byte[] buffer, uint length, string contentName, IntPtr session, out int result)
        => AmsiScanBuffer(context, buffer, length, contentName, session, out result);
    public void CloseSession(IntPtr context, IntPtr session) => AmsiCloseSession(context, session);
    public void Uninitialize(IntPtr context) => AmsiUninitialize(context);

    [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
    private static extern int AmsiInitialize(string appName, out IntPtr amsiContext);

    [DllImport("amsi.dll")]
    private static extern void AmsiUninitialize(IntPtr amsiContext);

    [DllImport("amsi.dll")]
    private static extern int AmsiOpenSession(IntPtr amsiContext, out IntPtr session);

    [DllImport("amsi.dll")]
    private static extern void AmsiCloseSession(IntPtr amsiContext, IntPtr session);

    [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
    private static extern int AmsiScanBuffer(
        IntPtr amsiContext, byte[] buffer, uint length, string contentName, IntPtr session, out int result);
}

/// <summary>
/// Scans validated tool arguments through AMSI before they reach JEA. This runs after
/// ParameterValidator, so AMSI only ever sees allowlist-conformant content: it is a second
/// opinion against known-malicious byte patterns, NOT an authorization or validation gate.
/// Fixed cmdlets, structured parameters, JEA and the policy gates remain the controls that
/// decide what may run; nothing is permitted merely because AMSI said "clean".
///
/// Failure semantics are explicit (<see cref="AmsiMode"/>): detected or admin-blocked content is
/// always denied; when AMSI cannot answer, BestEffort (default) continues with a warning and
/// Strict denies. Residual risk of BestEffort: on a host with no AMSI provider this layer does
/// nothing, so an argument that satisfies its regex/enum but carries a recognizable exploit
/// signature is not caught here.
/// </summary>
public sealed class AmsiScanner : IDisposable
{
    private const string AppName = "McpBroker";
    private const int AMSI_RESULT_BLOCKED_BY_ADMIN_START = 0x4000;
    private const int AMSI_RESULT_BLOCKED_BY_ADMIN_END = 0x4FFF;
    private const int AMSI_RESULT_DETECTED = 32768;

    private readonly ILogger<AmsiScanner> _logger;
    private readonly AmsiMode _mode;
    private readonly IAmsiApi _api;
    private readonly object _lock = new();
    private IntPtr _amsiContext = IntPtr.Zero;
    private IntPtr _session = IntPtr.Zero;
    private bool _initFailed;
    private bool _disposed;

    public AmsiScanner(ILogger<AmsiScanner> logger, AmsiMode mode = AmsiMode.BestEffort)
        : this(logger, mode, new NativeAmsiApi()) { }

    internal AmsiScanner(ILogger<AmsiScanner> logger, IAmsiApi api)
        : this(logger, AmsiMode.BestEffort, api) { }

    internal AmsiScanner(ILogger<AmsiScanner> logger, AmsiMode mode, IAmsiApi api)
    {
        _logger = logger;
        _mode = mode;
        _api = api;
    }

    public PolicyDecision Scan(string correlationId, IReadOnlyDictionary<string, string> parameters)
    {
        if (parameters.Count == 0) return PolicyDecision.Allow();

        if (!EnsureInitialized())
            return Unavailable("amsi-unavailable", correlationId, "AMSI is not available on this host");

        var content = JsonSerializer.Serialize(parameters);
        var buffer = Encoding.Unicode.GetBytes(content);

        try
        {
            int hr = _api.Scan(_amsiContext, buffer, (uint)buffer.Length,
                $"{AppName}:{correlationId}", _session, out var result);

            if (hr < 0)
            {
                _logger.LogWarning("AmsiScanBuffer failed (hr=0x{Hr:X8}) for {Corr}", hr, correlationId);
                return Unavailable("amsi-scan-failed", correlationId, "AMSI scan failed");
            }

            if (result >= AMSI_RESULT_BLOCKED_BY_ADMIN_START && result <= AMSI_RESULT_BLOCKED_BY_ADMIN_END)
            {
                _logger.LogWarning("AMSI content blocked by administrator policy for {Corr} (result={Result})",
                    correlationId, result);
                return PolicyDecision.Deny("amsi-blocked-by-admin");
            }

            if (result >= AMSI_RESULT_DETECTED)
            {
                _logger.LogWarning("AMSI flagged content as malicious for {Corr} (result={Result})",
                    correlationId, result);
                return PolicyDecision.Deny("amsi-detected-malicious-content");
            }

            return PolicyDecision.Allow();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "AMSI scan threw for {Corr}", correlationId);
            return Unavailable("amsi-scan-failed", correlationId, "AMSI scan threw");
        }
    }

    private PolicyDecision Unavailable(string reason, string correlationId, string detail)
    {
        if (_mode == AmsiMode.Strict)
        {
            _logger.LogWarning("{Detail} for {Corr}; denying (Amsi:Mode=Strict)", detail, correlationId);
            return PolicyDecision.Deny(reason);
        }

        _logger.LogWarning("{Detail} for {Corr}; continuing (Amsi:Mode=BestEffort)", detail, correlationId);
        return PolicyDecision.Allow();
    }

    private bool EnsureInitialized()
    {
        if (_amsiContext != IntPtr.Zero) return true;
        if (_initFailed) return false;

        lock (_lock)
        {
            if (_disposed) return false;
            if (_amsiContext != IntPtr.Zero) return true;
            if (_initFailed) return false;

            try
            {
                int hr = _api.Initialize(AppName, out var context);
                if (hr < 0)
                {
                    _logger.LogWarning("AmsiInitialize failed (hr=0x{Hr:X8}); AMSI unavailable for this process", hr);
                    _initFailed = true;
                    return false;
                }

                _amsiContext = context;
            }
            catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException
                                          or BadImageFormatException or InvalidOperationException)
            {
                _logger.LogWarning(ex, "AMSI library could not be used; AMSI unavailable for this process");
                _initFailed = true;
                return false;
            }

            try
            {
                int hr = _api.OpenSession(_amsiContext, out _session);
                if (hr < 0)
                {
                    _logger.LogWarning("AmsiOpenSession failed (hr=0x{Hr:X8}); scanning without a session", hr);
                    _session = IntPtr.Zero;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "AmsiOpenSession threw; scanning without a session");
                _session = IntPtr.Zero;
            }

            return true;
        }
    }

    public void Dispose()
    {
        lock (_lock)
        {
            if (_disposed) return;
            _disposed = true;
            try
            {
                if (_session != IntPtr.Zero) { _api.CloseSession(_amsiContext, _session); _session = IntPtr.Zero; }
                if (_amsiContext != IntPtr.Zero) { _api.Uninitialize(_amsiContext); _amsiContext = IntPtr.Zero; }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "AMSI cleanup failed");
            }
        }
    }
}

/// <summary>
/// Verifies single-use elicitation approvals. An approval is only valid for the exact
/// operation it was requested for: the same server-generated correlation id, the same tool,
/// and the same operation hash (tool + caller + parameters, so the target is covered).
/// </summary>
public sealed class ConsentEngine
{
    private readonly bool _requireDistinctApprover;
    private readonly HashSet<string> _approverSids;

    public ConsentEngine(bool requireDistinctApprover = false, IEnumerable<string>? approverSids = null)
    {
        _requireDistinctApprover = requireDistinctApprover;
        _approverSids = new HashSet<string>(approverSids ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
    }

    public static string HashParameters(IReadOnlyDictionary<string, string> parameters)
    {
        var canonical = JsonSerializer.Serialize(parameters.OrderBy(k => k.Key, StringComparer.Ordinal)
            .ToDictionary(k => k.Key, v => v.Value));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    /// <summary>
    /// Hash of the whole operation being approved: tool, requesting caller and parameters
    /// (which carry the target). Binding the tool and caller into the hash means a hash taken
    /// for one tool or one requester can never match an operation of another, independent of
    /// the separate tool-id comparison in <see cref="Verify"/>.
    /// </summary>
    public static string HashOperation(string toolId, string callerSid, IReadOnlyDictionary<string, string> parameters)
    {
        var canonical = JsonSerializer.Serialize(new
        {
            tool = toolId,
            caller = callerSid,
            parameters = parameters.OrderBy(k => k.Key, StringComparer.Ordinal).ToDictionary(k => k.Key, v => v.Value)
        });
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    /// <summary>
    /// Every argument is mandatory on purpose: there is no overload and no default that lets a
    /// caller skip the tool-identity comparison. Any missing identity fails closed.
    /// </summary>
    public PolicyDecision Verify(string correlationId, string expectedHash, string callerSid,
        string replyCorrelationId, string replyHash, bool approved, string decidedBySid,
        string expectedToolId, string replyToolId)
    {
        if (string.IsNullOrWhiteSpace(expectedToolId))
            return PolicyDecision.Deny("elicitation-tool-invalid");

        if (string.IsNullOrWhiteSpace(callerSid))
            return PolicyDecision.Deny("caller-identity-missing");

        if (string.IsNullOrWhiteSpace(decidedBySid))
            return PolicyDecision.Deny("approver-identity-missing");

        if (!string.Equals(correlationId, replyCorrelationId, StringComparison.Ordinal))
            return PolicyDecision.Deny("elicitation-correlation-mismatch");

        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(expectedHash), Encoding.UTF8.GetBytes(replyHash ?? string.Empty)))
            return PolicyDecision.Deny("elicitation-param-mismatch");

        // An explicit denial is reported as a denial whatever tool the reply names.
        if (!approved)
            return PolicyDecision.Deny("elicitation-denied");

        if (!string.Equals(expectedToolId, replyToolId, StringComparison.Ordinal))
            return PolicyDecision.Deny("elicitation-tool-mismatch");

        // A caller confirmation is never an authorization decision. This check is
        // unconditional so a configuration mistake cannot enable self-approval.
        if (string.Equals(decidedBySid, callerSid, StringComparison.OrdinalIgnoreCase))
            return PolicyDecision.Deny("self-approval-forbidden");

        // Distinct-approver mode additionally requires an explicitly allowlisted SID.
        if (_requireDistinctApprover)
        {
            if (!_approverSids.Contains(decidedBySid))
                return PolicyDecision.Deny("approver-not-authorized");
        }

        return PolicyDecision.Allow();
    }
}

/// <summary>
/// Server-side taint window. Once a caller is (or is about to be) handed output from a tool
/// that carries untrusted external data (AD attributes, file contents, network responses), that
/// caller is marked tainted for a window; write/destructive calls from a tainted caller are refused.
///
/// This is a conservative CALLER-LEVEL approximation of cross-turn prompt-injection risk, not
/// data-flow tracking: the broker cannot see what the LLM does with a value between calls, so it
/// cannot tell which later parameter came from which earlier output. It simply refuses to let a
/// caller that recently ingested untrusted data drive a mutating tool within the window. After
/// the window expires nothing remembers the earlier read.
/// </summary>
public sealed class TaintTracker
{
    private readonly int _windowSeconds;
    private readonly TimeProvider _clock;
    private readonly object _lock = new();
    private readonly Dictionary<string, DateTimeOffset> _taintedUntil = new(StringComparer.Ordinal);

    public TaintTracker(int windowSeconds = 300, TimeProvider? clock = null)
    {
        _windowSeconds = windowSeconds;
        _clock = clock ?? TimeProvider.System;
    }

    internal int TrackedCallerCount
    {
        get { lock (_lock) return _taintedUntil.Count; }
    }

    public void MarkTainted(string callerSid)
    {
        if (string.IsNullOrWhiteSpace(callerSid)) return;   // a blank identity is already treated as tainted

        var now = _clock.GetUtcNow();
        lock (_lock)
        {
            foreach (var expired in _taintedUntil.Where(kv => now > kv.Value).Select(kv => kv.Key).ToArray())
                _taintedUntil.Remove(expired);

            _taintedUntil[callerSid] = now.AddSeconds(_windowSeconds);
        }
    }

    public bool IsTainted(string callerSid)
    {
        // Fail closed: with no usable identity there is nothing to scope a clean bill of health to.
        if (string.IsNullOrWhiteSpace(callerSid)) return true;

        lock (_lock)
        {
            if (!_taintedUntil.TryGetValue(callerSid, out var until)) return false;
            if (_clock.GetUtcNow() > until) { _taintedUntil.Remove(callerSid); return false; }
            return true;
        }
    }
}
