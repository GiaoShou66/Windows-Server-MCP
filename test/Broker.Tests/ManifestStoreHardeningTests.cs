using System.Security.Cryptography;
using System.Text.Json;
using Broker.Core;
using Broker.Registry;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Broker.Tests;

public sealed class ManifestStoreHardeningTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"mcp-hardening-{Guid.NewGuid():N}");
    private string ManifestPath => Path.Combine(_dir, "manifest.json");

    public ManifestStoreHardeningTests() => Directory.CreateDirectory(_dir);

    private static object ToolJson(string id, string tier = "read", bool? requiresElicitation = null,
        string? enumValue = null, bool revoked = false)
    {
        var allow = enumValue is null
            ? (object)new { regexPattern = "^[a-z]+$" }
            : new { enumValues = new[] { enumValue } };
        var dict = new Dictionary<string, object?>
        {
            ["toolId"] = id,
            ["displayName"] = id,
            ["revoked"] = revoked,
            ["server"] = new { serverId = "s", path = @"C:\fake\s.psm1", signatureThumbprint = new string('A', 40) },
            ["riskTier"] = tier,
            ["jeaMapping"] = new { endpointName = "ep", roleCapabilityName = "rc-" + id, cmdlet = "Get-Thing", moduleName = "Get-Thing", accessGroup = "G" },
            ["parameters"] = new[] { new { name = "P", type = "string", required = false, allowlist = allow } },
            ["untrustedInputSources"] = Array.Empty<string>(),
            ["maskedFields"] = Array.Empty<string>()
        };
        if (requiresElicitation is not null) dict["requiresElicitation"] = requiresElicitation;
        return dict;
    }

    private void Write(params object[] tools) =>
        File.WriteAllText(ManifestPath, JsonSerializer.Serialize(new { tools }));

    private ManifestStore Open(bool integrity = false) =>
        new(ManifestPath, NullLogger<ManifestStore>.Instance, requireIntegrity: integrity);

    [Fact]
    public void ToolWithUnrecognizedRiskTierIsNotRegistered()
    {
        Write(ToolJson("good"), ToolJson("typo", tier: "wrte"), ToolJson("blank", tier: ""));
        using var store = Open();

        Assert.NotNull(store.Get("good"));
        Assert.Null(store.Get("typo"));
        Assert.Null(store.Get("blank"));
    }

    [Fact]
    public void DuplicateToolIdsAbortTheLoad()
    {
        Write(ToolJson("dup"), ToolJson("dup"));
        Assert.ThrowsAny<Exception>(() => Open());
    }

    [Fact]
    public void ToolWithoutAnIdIsNotRegistered()
    {
        Write(ToolJson("good"), ToolJson(""));
        using var store = Open();
        Assert.Single(store.All);
    }

    [Fact]
    public void HotReloadCannotAddATool()
    {
        Write(ToolJson("a"));
        using var store = Open();

        Write(ToolJson("a"), ToolJson("sneaky-new-tool"));
        store.ReloadNow();

        Assert.NotNull(store.Get("a"));
        Assert.Null(store.Get("sneaky-new-tool"));
    }

    [Fact]
    public void HotReloadCannotDowngradeATierOrDropElicitation()
    {
        Write(ToolJson("mutator", tier: "write"));
        using var store = Open();
        Assert.True(store.Get("mutator")!.ElicitationRequired);

        Write(ToolJson("mutator", tier: "read", requiresElicitation: false));
        store.ReloadNow();

        var after = store.Get("mutator");
        Assert.NotNull(after);
        Assert.Equal(RiskTier.Write, after!.RiskTier);
        Assert.True(after.ElicitationRequired);
    }

    [Fact]
    public void HotReloadCannotLoosenAParameterAllowlist()
    {
        Write(ToolJson("t", enumValue: "stop"));
        using var store = Open();

        Write(ToolJson("t", enumValue: "stop-everything"));
        store.ReloadNow();

        Assert.Equal(new[] { "stop" }, store.Get("t")!.Parameters.Single().Allowlist.EnumValues);
    }

    [Fact]
    public void HotReloadStillRevokesByRemovalAndByFlag()
    {
        Write(ToolJson("keep"), ToolJson("remove"), ToolJson("flag"));
        using var store = Open();
        var revoked = new List<string>();
        store.ToolsRevoked += ids => revoked.AddRange(ids);

        Write(ToolJson("keep"), ToolJson("flag", revoked: true));
        store.ReloadNow();

        Assert.NotNull(store.Get("keep"));
        Assert.Null(store.Get("remove"));
        Assert.Null(store.Get("flag"));
        Assert.Equal(new[] { "flag", "remove" }, revoked.OrderBy(x => x).ToArray());
    }

    [Fact]
    public void ReloadWithAFailedIntegrityCheckRevokesEveryTool()
    {
        Write(ToolJson("a"), ToolJson("b"));
        File.WriteAllText(ManifestPath + ".sha256", Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(ManifestPath))));
        using var store = Open(integrity: true);
        Assert.NotNull(store.Get("a"));

        var revoked = new List<string>();
        store.ToolsRevoked += ids => revoked.AddRange(ids);

        // Edited without refreshing the sidecar: fail closed, not "keep the old set".
        Write(ToolJson("a"), ToolJson("b"), ToolJson("c"));
        store.ReloadNow();

        Assert.Null(store.Get("a"));
        Assert.Null(store.Get("b"));
        Assert.Equal(new[] { "a", "b" }, revoked.OrderBy(x => x).ToArray());
    }

    [Fact]
    public void ReloadOfUnparseableJsonKeepsTheKnownGoodRegistry()
    {
        Write(ToolJson("a"));
        using var store = Open();

        File.WriteAllText(ManifestPath, "{ not json");
        Assert.ThrowsAny<JsonException>(() => store.ReloadNow());

        Assert.NotNull(store.Get("a"));
    }

    [Fact]
    public void HotReloadRevokesAnActiveToolWhoseTierBecomesUnrecognized()
    {
        Write(ToolJson("a", tier: "write"), ToolJson("b"));
        using var store = Open();
        var revoked = new List<string>();
        store.ToolsRevoked += ids => revoked.AddRange(ids);

        // A typo in a live edit must remove the tool, never leave it running or default it to read.
        Write(ToolJson("a", tier: "wrte"), ToolJson("b"));
        store.ReloadNow();

        Assert.Null(store.Get("a"));
        Assert.NotNull(store.Get("b"));
        Assert.Equal(new[] { "a" }, revoked);
    }

    [Fact]
    public async Task ARevocationDeliveredByAtomicRenameIsStillApplied()
    {
        Write(ToolJson("keep"), ToolJson("gone"));
        using var store = Open();
        var revoked = new TaskCompletionSource<IReadOnlyCollection<string>>();
        store.ToolsRevoked += ids => revoked.TrySetResult(ids);

        // The usual safe way to publish a file: write a temp file, then rename it over the target.
        var temp = Path.Combine(_dir, "manifest.json.tmp");
        File.WriteAllText(temp, JsonSerializer.Serialize(new { tools = new[] { ToolJson("keep") } }));
        File.Move(temp, ManifestPath, overwrite: true);

        var ids = await revoked.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Contains("gone", ids);
        Assert.Null(store.Get("gone"));
        Assert.NotNull(store.Get("keep"));
    }

    [Fact]
    public void RevokedToolIsInvisibleToGet()
    {
        Write(ToolJson("a", revoked: true));
        using var store = Open();
        Assert.Null(store.Get("a"));
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { }
    }
}

public sealed class ShippedManifestInvariantTests : IClassFixture<ShippedManifestFixture>
{
    private readonly ShippedManifestFixture _fx;
    public ShippedManifestInvariantTests(ShippedManifestFixture fx) => _fx = fx;

    [Fact]
    public void ShippedSidecarMatchesTheShippedManifestBytes()
    {
        var manifest = File.ReadAllBytes(RepoPaths.Combine("policy", "manifest.json"));
        var sidecar = File.ReadAllText(RepoPaths.Combine("policy", "manifest.json.sha256")).Trim();

        Assert.Equal(Convert.ToHexString(SHA256.HashData(manifest)), sidecar, ignoreCase: true);
    }

    [Fact]
    public void EveryShippedToolLoadsWithIntegrityEnforced()
    {
        // Counted from the file, not hard-coded, so adding a tool never needs a test edit.
        using var doc = JsonDocument.Parse(File.ReadAllText(RepoPaths.Combine("policy", "manifest.json")));
        var expected = doc.RootElement.GetProperty("tools").GetArrayLength();

        Assert.True(expected > 0);
        Assert.Equal(expected, _fx.Store.All.Count);
    }

    [Fact]
    public void EveryShippedToolHasARecognizedTier()
    {
        Assert.All(_fx.Store.All, t => Assert.True(t.HasRecognizedRiskTier, t.ToolId));
    }

    [Fact]
    public void EveryShippedWriteToolRequiresElicitationAndDeclaresADenyByDefaultScope()
    {
        var writers = _fx.Store.All.Where(t => t.RiskTier != RiskTier.Read).ToList();
        Assert.NotEmpty(writers);

        Assert.All(writers, t =>
        {
            Assert.True(t.ElicitationRequired, $"{t.ToolId} must require elicitation");
            Assert.NotEmpty(t.ResourceAllowlist);
            Assert.All(t.ResourceAllowlist.Values, list =>
                Assert.Empty(list));   // deny-all until an administrator scopes the tool
        });
    }

    [Fact]
    public void EveryShippedParameterHasASupportedTypeAndAConstraint()
    {
        foreach (var t in _fx.Store.All)
            foreach (var p in t.Parameters)
            {
                Assert.True(Broker.Policy.ParameterTypes.IsSupported(p.Type), $"{t.ToolId}.{p.Name} type '{p.Type}'");
                var a = p.Allowlist;
                Assert.True(a.MaxLength is not null || a.EnumValues is { Count: > 0 } || a.RegexPattern is not null || a.Range is not null,
                    $"{t.ToolId}.{p.Name} has no constraint");
            }
    }

    [Fact]
    public void EveryShippedWriteToolIsOnAWriteEndpointAndNoReadToolIs()
    {
        foreach (var t in _fx.Store.All)
        {
            bool writeEndpoint = t.JeaMapping.EndpointName.Contains("Write", StringComparison.Ordinal);
            Assert.Equal(t.RiskTier != RiskTier.Read, writeEndpoint);
        }
    }
}
