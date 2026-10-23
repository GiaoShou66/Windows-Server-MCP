using System.Globalization;
using Broker.Core;
using Broker.JeaExecution;
using Broker.Registry;
using Xunit;

namespace Broker.Tests;

/// <summary>
/// The generator writes the files that decide which cmdlets JEA exposes. Manifest strings are
/// interpolated into PowerShell data files, so each identifier must be a plain identifier.
/// </summary>
public sealed class JeaConfigGeneratorInputTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"mcp-gen-input-{Guid.NewGuid():N}");

    private static ToolManifest Tool(Action<ToolManifest>? mutate = null)
    {
        var t = new ToolManifest
        {
            ToolId = "t", Description = "d", RiskTierRaw = "read",
            JeaMapping = new JeaMapping
            {
                EndpointName = "McpBroker.Test", RoleCapabilityName = "DoThing", Cmdlet = "Get-Thing",
                ModuleName = "Get-Thing", AccessGroup = @"CONTOSO\Callers", UseGmsa = false
            },
            Parameters =
            {
                new ToolParameter { Name = "Count", Type = "int", Allowlist = new ParameterAllowlist { Range = new ParamRange { Min = 1, Max = 30 } } }
            }
        };
        mutate?.Invoke(t);
        return t;
    }

    public static IEnumerable<object[]> Hostile() => new (string, Action<ToolManifest>)[]
    {
        ("cmdlet quote injection", t => t.JeaMapping.Cmdlet = "Get-Thing'; } ; @{ Name = 'Invoke-Expression"),
        ("cmdlet with a space", t => t.JeaMapping.Cmdlet = "Get-Thing -Force"),
        ("cmdlet with a newline", t => t.JeaMapping.Cmdlet = "Get-Thing\nInvoke-Expression"),
        ("cmdlet without a verb", t => t.JeaMapping.Cmdlet = "Thing"),
        ("empty cmdlet", t => t.JeaMapping.Cmdlet = ""),
        ("module quote injection", t => t.JeaMapping.ModuleName = "Get-Thing'; evil"),
        ("module path traversal", t => t.JeaMapping.ModuleName = @"..\..\evil"),
        ("role capability path traversal", t => t.JeaMapping.RoleCapabilityName = @"..\evil"),
        ("role capability with a slash", t => t.JeaMapping.RoleCapabilityName = "a/b"),
        ("role capability with a dot", t => t.JeaMapping.RoleCapabilityName = "x.psrc"),
        ("endpoint with a quote", t => t.JeaMapping.EndpointName = "a'b"),
        ("endpoint with a newline", t => t.JeaMapping.EndpointName = "a\nb"),
        ("endpoint with a space", t => t.JeaMapping.EndpointName = "a b"),
        ("access group quote injection", t => t.JeaMapping.AccessGroup = @"CONTOSO\G'; x"),
        ("access group newline", t => t.JeaMapping.AccessGroup = "G\nH"),
        ("gmsa quote injection", t => { t.JeaMapping.UseGmsa = true; t.JeaMapping.GmsaAccount = "svc$'; x"; }),
        ("gmsa required but missing", t => { t.JeaMapping.UseGmsa = true; t.JeaMapping.GmsaAccount = null; }),
        ("virtual account group injection", t => t.JeaMapping.VirtualAccountGroups = new() { "Administrators'; x" }),
        ("external command with arguments", t => t.JeaMapping.ExternalCommands = new() { "whoami.exe /c" }),
        ("external command without .exe", t => t.JeaMapping.ExternalCommands = new() { "cmd" }),
        ("external command path traversal", t => t.JeaMapping.ExternalCommands = new() { @"..\x.exe" }),
        ("parameter name injection", t => t.Parameters[0].Name = "Count'; } @{ Name='Evil"),
        ("parameter name with a space", t => t.Parameters[0].Name = "Count Name"),
        ("range NaN", t => t.Parameters[0].Allowlist.Range = new ParamRange { Min = double.NaN, Max = 3 }),
        ("range infinity", t => t.Parameters[0].Allowlist.Range = new ParamRange { Min = 1, Max = double.PositiveInfinity }),
        ("range min above max", t => t.Parameters[0].Allowlist.Range = new ParamRange { Min = 9, Max = 3 }),
    }.Select(c => new object[] { c.Item1, c.Item2 });

    [Theory]
    [MemberData(nameof(Hostile))]
    public void HostileManifestValuesAreRefusedAndNothingIsWritten(string why, Action<ToolManifest> mutate)
    {
        var tool = Tool(mutate);

        var ex = Assert.Throws<InvalidOperationException>(() => new JeaConfigGenerator(_dir).GenerateAll(new[] { tool }));

        Assert.False(string.IsNullOrWhiteSpace(ex.Message), why);
        Assert.False(Directory.Exists(_dir) && Directory.EnumerateFileSystemEntries(_dir).Any(), $"{why}: files were written");
    }

    [Fact]
    public void OneBadToolStopsTheWholeRunBeforeAnyFileIsWritten()
    {
        var good = Tool();
        var bad = Tool(t => { t.ToolId = "bad"; t.JeaMapping.RoleCapabilityName = "Other"; t.JeaMapping.Cmdlet = "Get-X'; evil"; });

        Assert.Throws<InvalidOperationException>(() => new JeaConfigGenerator(_dir).GenerateAll(new[] { good, bad }));

        Assert.False(Directory.Exists(_dir) && Directory.EnumerateFileSystemEntries(_dir).Any());
    }

    [Fact]
    public void ARefusalNamesTheToolAndTheFieldButNeverEchoesTheHostileValue()
    {
        var ex = Assert.Throws<InvalidOperationException>(() =>
            new JeaConfigGenerator(_dir).GenerateAll(new[] { Tool(t => t.JeaMapping.Cmdlet = "Get-Thing'; Invoke-Expression") }));

        Assert.Contains("cmdlet", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Invoke-Expression", ex.Message);
    }

    [Fact]
    public void ValidValuesGenerateExactlyTheExpectedGrants()
    {
        var files = new JeaConfigGenerator(_dir).GenerateAll(new[] { Tool() });
        var psrc = File.ReadAllText(files.Single(f => f.EndsWith("DoThing.psrc")));

        Assert.Contains("Name = 'Get-Thing'", psrc);
        Assert.Contains("ModulesToImport = @('Get-Thing')", psrc);
        // Exactly one cmdlet grant: the VisibleCmdlets entry is the only hashtable that opens on its own line.
        Assert.Single(System.Text.RegularExpressions.Regex.Matches(psrc, @"@\{\s*\n\s*Name = '"));
    }

    [Fact]
    public void RangesAreFormattedWithTheInvariantCulture()
    {
        var original = CultureInfo.CurrentCulture;
        try
        {
            var odd = (CultureInfo)CultureInfo.InvariantCulture.Clone();
            odd.NumberFormat.NumberDecimalSeparator = ",";
            CultureInfo.CurrentCulture = odd;

            var files = new JeaConfigGenerator(_dir).GenerateAll(new[]
            {
                Tool(t => t.Parameters[0].Allowlist.Range = new ParamRange { Min = 1.5, Max = 2.5 })
            });

            var psrc = File.ReadAllText(files.Single(f => f.EndsWith(".psrc")));
            Assert.Contains("ValidateRange = 1.5,2.5", psrc);
        }
        finally { CultureInfo.CurrentCulture = original; }
    }

    [Fact]
    public void AStaleGeneratedFileInTheOutputDirectoryStopsTheRun()
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(Path.Combine(_dir, "RemovedTool.psrc"), "@{ VisibleCmdlets = @('Remove-Everything') }");
        File.WriteAllText(Path.Combine(_dir, "McpBroker.Gone.pssc"), "@{}");

        var ex = Assert.Throws<InvalidOperationException>(() => new JeaConfigGenerator(_dir).GenerateAll(new[] { Tool() }));

        Assert.Contains("RemovedTool.psrc", ex.Message);
        Assert.Contains("McpBroker.Gone.pssc", ex.Message);
        // Nothing was generated and nothing was deleted.
        Assert.False(File.Exists(Path.Combine(_dir, "DoThing.psrc")));
        Assert.True(File.Exists(Path.Combine(_dir, "RemovedTool.psrc")));
    }

    [Fact]
    public void RegeneratingOverTheSameFilesIsAllowedAndOverwritesThem()
    {
        var generator = new JeaConfigGenerator(_dir);
        generator.GenerateAll(new[] { Tool() });
        File.WriteAllText(Path.Combine(_dir, "DoThing.psrc"), "STALE CONTENT");

        generator.GenerateAll(new[] { Tool() });

        Assert.DoesNotContain("STALE", File.ReadAllText(Path.Combine(_dir, "DoThing.psrc")));
    }

    [Fact]
    public void UnrelatedFilesInTheOutputDirectoryAreLeftAlone()
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(Path.Combine(_dir, "notes.txt"), "keep me");

        new JeaConfigGenerator(_dir).GenerateAll(new[] { Tool() });

        Assert.Equal("keep me", File.ReadAllText(Path.Combine(_dir, "notes.txt")));
    }

    [Fact]
    public void EveryShippedToolPassesTheIdentifierChecks()
    {
        using var fx = new ShippedManifestFixture();
        var files = new JeaConfigGenerator(_dir).GenerateAll(fx.Store.All.ToList());
        Assert.Equal(fx.Store.All.Count + fx.Store.All.Select(t => t.JeaMapping.EndpointName).Distinct().Count(), files.Count);
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_dir)) Directory.Delete(_dir, true); } catch { }
    }
}
