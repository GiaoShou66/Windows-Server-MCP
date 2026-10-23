using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Broker.Core;
using Broker.Registry;
using Microsoft.Extensions.Logging;

namespace Broker.Policy;

/// <summary>
/// Validates caller parameters against the per-parameter allowlist in the manifest.
/// Broker-side defense in depth; JEA re-validates independently inside the session.
/// </summary>
public sealed class ParameterValidator
{
    public PolicyDecision Validate(ToolManifest tool, IReadOnlyDictionary<string, string> supplied)
    {
        // reject unknown parameters outright
        var known = tool.Parameters.Select(p => p.Name).ToHashSet(StringComparer.Ordinal);
        foreach (var key in supplied.Keys)
            if (!known.Contains(key))
                return PolicyDecision.Deny($"unknown-parameter:{key}");

        foreach (var p in tool.Parameters)
        {
            var present = supplied.TryGetValue(p.Name, out var value);
            if (!present)
            {
                if (p.Required) return PolicyDecision.Deny($"missing-required-parameter:{p.Name}");
                continue;
            }

            var reason = CheckOne(p, value!);
            if (reason is not null) return PolicyDecision.Deny(reason);

            if (tool.ResourceAllowlist.TryGetValue(p.Name, out var allowedResources) &&
                !allowedResources.Contains(value!, StringComparer.OrdinalIgnoreCase))
                return PolicyDecision.Deny($"resource-not-allowlisted:{p.Name}");
        }

        return PolicyDecision.Allow();
    }

    private static string? CheckOne(ToolParameter p, string value)
    {
        var a = p.Allowlist;

        if (a.MaxLength is { } max && value.Length > max)
            return $"parameter-too-long:{p.Name}";

        if (a.EnumValues is { Count: > 0 } set && !set.Contains(value, StringComparer.Ordinal))
            return $"parameter-not-in-enum:{p.Name}";

        if (a.RegexPattern is { } pattern &&
            !Regex.IsMatch(value, pattern, RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100)))
            return $"parameter-pattern-mismatch:{p.Name}";

        if (a.Range is { } range)
        {
            if (!double.TryParse(value, out var num)) return $"parameter-not-numeric:{p.Name}";
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

/// <summary>Per-caller sliding-window rate limiter. Separate budget for destructive calls.</summary>
public sealed class RateLimiter
{
    private readonly int _callsPerMinute;
    private readonly int _destructivePerHour;
    private readonly object _lock = new();
    private readonly Dictionary<string, Queue<DateTimeOffset>> _all = new();
    private readonly Dictionary<string, Queue<DateTimeOffset>> _destructive = new();

    public RateLimiter(int callsPerMinute = 60, int destructivePerHour = 10)
    {
        _callsPerMinute = callsPerMinute;
        _destructivePerHour = destructivePerHour;
    }

    public PolicyDecision Check(string callerSid, RiskTier tier)
    {
        var now = DateTimeOffset.UtcNow;
        lock (_lock)
        {
            if (!Allow(_all, callerSid, now, TimeSpan.FromMinutes(1), _callsPerMinute))
                return PolicyDecision.Deny("rate-limit-exceeded");

            if (tier is RiskTier.Destructive &&
                !Allow(_destructive, callerSid, now, TimeSpan.FromHours(1), _destructivePerHour))
                return PolicyDecision.Deny("destructive-rate-limit-exceeded");

            return PolicyDecision.Allow();
        }
    }

    private static bool Allow(Dictionary<string, Queue<DateTimeOffset>> map,
        string sid, DateTimeOffset now, TimeSpan window, int max)
    {
        if (!map.TryGetValue(sid, out var q)) { q = new(); map[sid] = q; }
        while (q.Count > 0 && now - q.Peek() > window) q.Dequeue();
        if (q.Count >= max) return false;
        q.Enqueue(now);
        return true;
    }
}

/// <summary>
/// Builds the argument set for a JEA cmdlet invocation as a typed dictionary — never a
/// composed shell/command string. Refuses any parameter not backed by an allowlist entry.
/// </summary>
public sealed class ArgvBuilder
{
    public IReadOnlyDictionary<string, object> Build(ToolManifest tool, IReadOnlyDictionary<string, string> supplied)
    {
        var argv = new Dictionary<string, object>(StringComparer.Ordinal);

        foreach (var p in tool.Parameters)
        {
            bool hasConstraint = p.Allowlist.MaxLength is not null || p.Allowlist.EnumValues is { Count: > 0 }
                || p.Allowlist.RegexPattern is not null || p.Allowlist.Range is not null;
            if (!hasConstraint)
                throw new InvalidOperationException($"Refusing to build call: parameter {p.Name} has no allowlist.");

            if (!supplied.TryGetValue(p.Name, out var raw)) continue;

            argv[p.Name] = p.Type switch
            {
                "int" => int.Parse(raw),
                "bool" => bool.Parse(raw),
                _ => raw
            };
        }

        return argv;
    }
}

/// <summary>
/// Scans validated tool arguments through AMSI (amsi.dll) before they reach JEA. This runs
/// after ParameterValidator, so AMSI sees only allowlist-conformant content — it is a second
/// opinion against known-malicious byte patterns (e.g. an enum/regex-valid string that still
/// contains a recognized exploit signature), not the primary input gate.
/// A session is opened once per process and closed on disposal; a scan failure (AMSI
/// unavailable, no registered provider) fails open with a logged warning, since AMSI absence
/// must not block legitimate read-tier operation — the allowlist gates remain the hard stop.
/// </summary>
public sealed class AmsiScanner : IDisposable
{
    private const string AppName = "McpBroker";
    private readonly ILogger<AmsiScanner> _logger;
    private readonly object _lock = new();
    private IntPtr _amsiContext = IntPtr.Zero;
    private IntPtr _session = IntPtr.Zero;
    private bool _initFailed;

    public AmsiScanner(ILogger<AmsiScanner> logger) => _logger = logger;

    public PolicyDecision Scan(string correlationId, IReadOnlyDictionary<string, string> parameters)
    {
        if (parameters.Count == 0) return PolicyDecision.Allow();

        if (!EnsureInitialized())
            return PolicyDecision.Allow(); // fail open: AMSI unavailable is not a policy gate

        var content = JsonSerializer.Serialize(parameters);
        var buffer = Encoding.Unicode.GetBytes(content);

        try
        {
            int hr = AmsiScanBuffer(_amsiContext, buffer, (uint)buffer.Length,
                $"{AppName}:{correlationId}", _session, out var result);

            if (hr < 0)
            {
                _logger.LogWarning("AmsiScanBuffer failed (hr=0x{Hr:X8}) for {Corr}; failing open", hr, correlationId);
                return PolicyDecision.Allow();
            }

            if (AmsiResultIsMalware(result))
            {
                _logger.LogWarning("AMSI flagged content as malicious for {Corr} (result={Result})",
                    correlationId, result);
                return PolicyDecision.Deny("amsi-detected-malicious-content");
            }

            return PolicyDecision.Allow();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "AMSI scan threw for {Corr}; failing open", correlationId);
            return PolicyDecision.Allow();
        }
    }

    private bool EnsureInitialized()
    {
        if (_amsiContext != IntPtr.Zero) return true;
        if (_initFailed) return false;

        lock (_lock)
        {
            if (_amsiContext != IntPtr.Zero) return true;
            if (_initFailed) return false;

            int hr = AmsiInitialize(AppName, out _amsiContext);
            if (hr < 0)
            {
                _logger.LogWarning("AmsiInitialize failed (hr=0x{Hr:X8}); AMSI scanning disabled for this process", hr);
                _initFailed = true;
                return false;
            }

            hr = AmsiOpenSession(_amsiContext, out _session);
            if (hr < 0)
            {
                _logger.LogWarning("AmsiOpenSession failed (hr=0x{Hr:X8}); scanning without a session", hr);
                _session = IntPtr.Zero;
            }

            return true;
        }
    }

    private static bool AmsiResultIsMalware(int result) =>
        result >= AMSI_RESULT_DETECTED;

    private const int AMSI_RESULT_DETECTED = 32768;

    public void Dispose()
    {
        lock (_lock)
        {
            if (_session != IntPtr.Zero) { AmsiCloseSession(_amsiContext, _session); _session = IntPtr.Zero; }
            if (_amsiContext != IntPtr.Zero) { AmsiUninitialize(_amsiContext); _amsiContext = IntPtr.Zero; }
        }
    }

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

/// <summary>Verifies single-use elicitation approvals: correct call, matching params, approved.</summary>
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

    public PolicyDecision Verify(string correlationId, string expectedHash, string callerSid,
        string replyCorrelationId, string replyHash, bool approved, string decidedBySid,
        string? expectedToolId = null, string? replyToolId = null)
    {
        if (!string.Equals(correlationId, replyCorrelationId, StringComparison.Ordinal))
            return PolicyDecision.Deny("elicitation-correlation-mismatch");

        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(expectedHash), Encoding.UTF8.GetBytes(replyHash)))
            return PolicyDecision.Deny("elicitation-param-mismatch");

        if (!approved)
            return PolicyDecision.Deny("elicitation-denied");

        if (expectedToolId is not null &&
            !string.Equals(expectedToolId, replyToolId, StringComparison.Ordinal))
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
/// Server-side taint window. Once a caller receives output from a tool that carries
/// untrusted external data (AD attributes, file contents, network responses), that caller
/// is marked tainted for a window; destructive calls from a tainted caller are refused.
///
/// This is a conservative approximation of cross-turn prompt-injection risk: the broker
/// cannot see what the LLM does between calls, but it can refuse to let a caller that just
/// ingested untrusted data turn around and drive a destructive tool within the window.
/// </summary>
public sealed class TaintTracker
{
    private readonly int _windowSeconds;
    private readonly object _lock = new();
    private readonly Dictionary<string, DateTimeOffset> _taintedUntil = new(StringComparer.Ordinal);

    public TaintTracker(int windowSeconds = 300) => _windowSeconds = windowSeconds;

    public void MarkTainted(string callerSid)
    {
        lock (_lock)
            _taintedUntil[callerSid] = DateTimeOffset.UtcNow.AddSeconds(_windowSeconds);
    }

    public bool IsTainted(string callerSid)
    {
        lock (_lock)
        {
            if (!_taintedUntil.TryGetValue(callerSid, out var until)) return false;
            if (DateTimeOffset.UtcNow > until) { _taintedUntil.Remove(callerSid); return false; }
            return true;
        }
    }
}
