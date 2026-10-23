using Broker.Core;
using Broker.JeaExecution;
using Broker.Registry;
using Xunit;

namespace Broker.Tests;

/// <summary>
/// A fact that runs only on Windows and is reported as SKIPPED (never as passed) elsewhere.
/// Used for tests that need Windows-only OS facilities: WinVerifyTrust, named-pipe ACLs,
/// impersonation, amsi.dll, WSMan, and Windows PowerShell.
/// </summary>
public sealed class WindowsOnlyFactAttribute : FactAttribute
{
    public WindowsOnlyFactAttribute()
    {
        if (!OperatingSystem.IsWindows())
            Skip = "Requires Windows (OS facility not available on this platform); NOT executed here.";
    }
}

/// <summary>Executor double that records every invocation. A denied request must leave Calls at zero.</summary>
internal sealed class SpyJeaExecutor : IJeaExecutor
{
    private int _calls;
    private readonly Func<ToolManifest, JeaInvocationResult>? _result;

    public SpyJeaExecutor(Func<ToolManifest, JeaInvocationResult>? result = null) => _result = result;

    public int Calls => Volatile.Read(ref _calls);
    public List<(string ToolId, IReadOnlyDictionary<string, object> Argv)> Invocations { get; } = new();

    public Task<JeaInvocationResult> InvokeAsync(
        ToolManifest tool, IReadOnlyDictionary<string, object> argv, CallContext context, CancellationToken ct)
    {
        Interlocked.Increment(ref _calls);
        lock (Invocations) Invocations.Add((tool.ToolId, argv));
        var now = DateTimeOffset.UtcNow;
        return Task.FromResult(_result?.Invoke(tool)
            ?? new JeaInvocationResult(true, 0, "[]", 1, now, now));
    }
}

/// <summary>Locates checked-in repository files (manifest, wrappers, scripts) from the test binary.</summary>
internal static class RepoPaths
{
    public static string Root { get; } = FindRoot();

    public static string Combine(params string[] parts) => Path.Combine(new[] { Root }.Concat(parts).ToArray());

    private static string FindRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "mcp-broker.sln")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("Repository root (mcp-broker.sln) not found.");
    }
}

/// <summary>Manually advanced clock so expiry and window tests are deterministic (no Thread.Sleep).</summary>
internal sealed class ManualTimeProvider : TimeProvider
{
    private DateTimeOffset _now;
    public ManualTimeProvider(DateTimeOffset? start = null) => _now = start ?? new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);
    public override DateTimeOffset GetUtcNow() => _now;
    public void Advance(TimeSpan by) => _now += by;
}
