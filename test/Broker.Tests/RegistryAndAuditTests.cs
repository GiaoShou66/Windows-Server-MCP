using Broker.Audit;
using Broker.Registry;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Broker.Tests;

/// <summary>
/// Revocation is the fast kill switch (design 6.5): editing the manifest file must hot-reload
/// and fire ToolsRevoked without a service restart. This is the first test of that path —
/// it exercises the real FileSystemWatcher, not just the in-memory dictionary diff.
/// </summary>
public sealed class ManifestStoreRevocationTests : IDisposable
{
    private readonly string _path;

    public ManifestStoreRevocationTests()
        => _path = Path.Combine(Path.GetTempPath(), $"mcp-test-revoke-{Guid.NewGuid():N}.json");

    private static string ManifestWith(params (string id, bool revoked)[] tools)
    {
        var entries = tools.Select(t => $$"""
            {
              "toolId": "{{t.id}}",
              "displayName": "{{t.id}}",
              "revoked": {{(t.revoked ? "true" : "false")}},
              "server": { "serverId": "s", "path": "C:\\fake\\s.psm1", "signatureThumbprint": "{{new string('A', 40)}}" },
              "riskTier": "read",
              "jeaMapping": { "endpointName": "ep", "roleCapabilityName": "rc-{{t.id}}", "cmdlet": "Get-Thing", "moduleName": "Get-Thing", "accessGroup": "G" },
              "parameters": [],
              "untrustedInputSources": [],
              "maskedFields": []
            }
            """);
        return "{ \"tools\": [" + string.Join(",", entries) + "] }";
    }

    [Fact]
    public async Task RemovingAToolFiresToolsRevoked()
    {
        File.WriteAllText(_path, ManifestWith(("tool-a", false), ("tool-b", false)));

        using var store = new ManifestStore(_path, NullLogger<ManifestStore>.Instance);
        Assert.NotNull(store.Get("tool-a"));
        Assert.NotNull(store.Get("tool-b"));

        var revoked = new TaskCompletionSource<IReadOnlyCollection<string>>();
        store.ToolsRevoked += ids => revoked.TrySetResult(ids);

        // Rewrite the manifest without tool-b.
        File.WriteAllText(_path, ManifestWith(("tool-a", false)));

        var result = await revoked.Task.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Contains("tool-b", result);
        Assert.NotNull(store.Get("tool-a"));
        Assert.Null(store.Get("tool-b"));
    }

    [Fact]
    public async Task MarkingRevokedTrueAlsoHidesTheTool()
    {
        File.WriteAllText(_path, ManifestWith(("tool-c", false)));
        using var store = new ManifestStore(_path, NullLogger<ManifestStore>.Instance);
        Assert.NotNull(store.Get("tool-c"));

        var revoked = new TaskCompletionSource<IReadOnlyCollection<string>>();
        store.ToolsRevoked += ids => revoked.TrySetResult(ids);

        File.WriteAllText(_path, ManifestWith(("tool-c", true)));

        await revoked.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Null(store.Get("tool-c"));
    }

    /// <summary>
    /// Regression test for a reload race: FileSystemWatcher can deliver Changed/Created on
    /// multiple threadpool threads concurrently. Without serializing Reload(), overlapping
    /// saves could each snapshot a stale "before" set and race on Load(), producing an
    /// incorrect ToolsRevoked diff. This fires many rapid successive edits — the kind of
    /// burst a script or editor autosave produces — and asserts the store converges to the
    /// correct final state with no exception escaping the watcher's background thread.
    /// </summary>
    [Fact]
    public async Task RapidSuccessiveEditsConvergeToCorrectFinalStateWithoutDeadlock()
    {
        File.WriteAllText(_path, ManifestWith(("tool-a", false), ("tool-b", false), ("tool-c", false)));
        using var store = new ManifestStore(_path, NullLogger<ManifestStore>.Instance);

        var allRevoked = new System.Collections.Concurrent.ConcurrentBag<string>();
        store.ToolsRevoked += ids => { foreach (var id in ids) allRevoked.Add(id); };

        // Simulate a burst: each write removes one more tool than the last.
        File.WriteAllText(_path, ManifestWith(("tool-a", false), ("tool-b", false)));
        File.WriteAllText(_path, ManifestWith(("tool-a", false)));
        File.WriteAllText(_path, ManifestWith());

        // Poll rather than fixed-sleep: the 150ms debounce plus lock serialization means
        // the last write's Reload may still be queued behind earlier ones.
        var deadline = DateTimeOffset.UtcNow.AddSeconds(15);
        while (DateTimeOffset.UtcNow < deadline && store.Get("tool-a") is not null)
            await Task.Delay(100);

        Assert.Null(store.Get("tool-a"));
        Assert.Null(store.Get("tool-b"));
        Assert.Null(store.Get("tool-c"));
        Assert.Contains("tool-a", allRevoked);
        Assert.Contains("tool-b", allRevoked);
        Assert.Contains("tool-c", allRevoked);
    }

    [Fact]
    public void MalformedReloadKeepsPreviousRegistryFailClosed()
    {
        File.WriteAllText(_path, ManifestWith(("tool-d", false)));
        using var store = new ManifestStore(_path, NullLogger<ManifestStore>.Instance);
        Assert.NotNull(store.Get("tool-d"));

        File.WriteAllText(_path, "{ not valid json ");
        // Give the watcher's debounce + reload a moment to run and fail.
        Thread.Sleep(500);

        // Fail-closed: a parse error must not widen access or wipe the known-good set.
        Assert.NotNull(store.Get("tool-d"));
    }

    public void Dispose()
    {
        try { File.Delete(_path); } catch { }
    }
}

public sealed class CorrelationLogTests : IDisposable
{
    private readonly string _path;
    public CorrelationLogTests() => _path = Path.Combine(Path.GetTempPath(), $"mcp-test-corr-{Guid.NewGuid():N}.log");

    [Fact]
    public void AppendedEntriesRoundTripThroughReadSince()
    {
        var log = new CorrelationLog(_path);
        var now = DateTimeOffset.UtcNow;

        log.Append(new CorrelationEntry("corr-1", "SID-1", "tool-a", "ep.read", now, now.AddSeconds(1)));
        log.Append(new CorrelationEntry("corr-2", "SID-2", "tool-b", "ep.write", now.AddSeconds(2), now.AddSeconds(3)));

        var entries = log.ReadSince(now.AddSeconds(-10));

        Assert.Equal(2, entries.Count);
        Assert.Contains(entries, e => e.CorrelationId == "corr-1" && e.ToolId == "tool-a");
        Assert.Contains(entries, e => e.CorrelationId == "corr-2" && e.EndpointName == "ep.write");
    }

    [Fact]
    public void ReadSinceExcludesEntriesBeforeTheWindow()
    {
        var log = new CorrelationLog(_path);
        var old = DateTimeOffset.UtcNow.AddHours(-2);
        var recent = DateTimeOffset.UtcNow;

        log.Append(new CorrelationEntry("old-corr", "SID", "tool-a", "ep", old, old.AddSeconds(1)));
        log.Append(new CorrelationEntry("new-corr", "SID", "tool-a", "ep", recent, recent.AddSeconds(1)));

        var entries = log.ReadSince(DateTimeOffset.UtcNow.AddMinutes(-1));

        Assert.DoesNotContain(entries, e => e.CorrelationId == "old-corr");
        Assert.Contains(entries, e => e.CorrelationId == "new-corr");
    }

    [Fact]
    public void ReadSinceOnMissingFileReturnsEmpty()
    {
        var log = new CorrelationLog(Path.Combine(Path.GetTempPath(), $"mcp-test-missing-{Guid.NewGuid():N}.log"));
        Assert.Empty(log.ReadSince(DateTimeOffset.UtcNow.AddDays(-1)));
    }

    public void Dispose()
    {
        try { File.Delete(_path); } catch { }
    }
}
