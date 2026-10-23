using System.Text.RegularExpressions;
using Broker.JeaExecution;
using Broker.Policy;
using Broker.Registry;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Broker.Tests;

/// <summary>
/// Fixture that loads the SHIPPED policy/manifest.json (copied with its integrity sidecar into a
/// temp directory) through the real ManifestStore, so patterns are tested after JSON decoding,
/// exactly as the validator and JEA generator see them.
/// </summary>
public sealed class ShippedManifestFixture : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"mcp-shipped-{Guid.NewGuid():N}");
    public ManifestStore Store { get; }

    public ShippedManifestFixture()
    {
        Directory.CreateDirectory(_dir);
        File.Copy(RepoPaths.Combine("policy", "manifest.json"), Path.Combine(_dir, "manifest.json"));
        File.Copy(RepoPaths.Combine("policy", "manifest.json.sha256"), Path.Combine(_dir, "manifest.json.sha256"));
        Store = new ManifestStore(Path.Combine(_dir, "manifest.json"), NullLogger<ManifestStore>.Instance, requireIntegrity: true);
    }

    /// <summary>Returns a private deep copy so tests may mutate it (e.g. scope lists) without
    /// leaking state into other tests that share this fixture.</summary>
    public ToolManifest Tool(string id) =>
        System.Text.Json.JsonSerializer.Deserialize<ToolManifest>(
            System.Text.Json.JsonSerializer.Serialize(Store.All.Single(t => t.ToolId == id)))!;

    public void Dispose()
    {
        Store.Dispose();
        try { Directory.Delete(_dir, true); } catch { }
    }
}

public sealed class TaskPathValidationTests : IClassFixture<ShippedManifestFixture>
{
    private const string ToolId = "set-scheduled-task-state";
    private readonly ShippedManifestFixture _fx;
    private readonly ParameterValidator _validator = new();

    public TaskPathValidationTests(ShippedManifestFixture fx) => _fx = fx;

    private string Pattern() =>
        _fx.Tool(ToolId).Parameters.Single(p => p.Name == "TaskPath").Allowlist.RegexPattern!;

    /// <summary>Validates TaskPath through the real ParameterValidator with the resource scope opened,
    /// so only the syntax rules (pattern + maxLength) are under test.</summary>
    private PolicyDecisionView Validate(string? taskPath)
    {
        var tool = _fx.Tool(ToolId);
        tool.ResourceAllowlist.Clear();
        var supplied = new Dictionary<string, string>
        {
            ["TaskPath"] = taskPath!,
            ["TaskName"] = "MyTask",
            ["Enabled"] = "true"
        };
        var d = _validator.Validate(tool, supplied);
        return new PolicyDecisionView(d.Allowed, d.Reason);
    }

    private sealed record PolicyDecisionView(bool Allowed, string? Reason);

    [Theory]
    [InlineData(@"\")]
    [InlineData(@"\Microsoft\")]
    [InlineData(@"\Microsoft\Windows\")]
    [InlineData(@"\Microsoft\Windows\.NET Framework\")]
    [InlineData(@"\My Folder\Sub_Folder-1\")]
    [InlineData(@"\a\b\c\d\e\")]
    public void LegitimateTaskSchedulerFoldersAreAccepted(string path)
    {
        var d = Validate(path);
        Assert.True(d.Allowed, $"'{path}' rejected: {d.Reason}");
    }

    [Theory]
    [InlineData("", "empty")]
    [InlineData("Microsoft\\", "missing leading separator")]
    [InlineData(@"\Microsoft", "missing trailing separator")]
    [InlineData(@"\\", "empty segment (double separator)")]
    [InlineData(@"\Microsoft\\Windows\", "empty interior segment")]
    [InlineData(@"\..\", "parent traversal")]
    [InlineData(@"\Microsoft\..\Windows\", "interior traversal")]
    [InlineData(@"\.\", "current-dir segment")]
    [InlineData(@"\...\", "dots-only segment")]
    [InlineData("/Microsoft/", "forward slashes")]
    [InlineData(@"C:\Microsoft\", "drive-qualified path")]
    [InlineData(@"\\server\share\", "UNC path")]
    [InlineData(@"\Micro*\", "wildcard would match several folders")]
    [InlineData(@"\Micro?\", "wildcard")]
    [InlineData(@"\Microsoft\ ", "trailing space after separator")]
    [InlineData(@"\Microsoft\Windows\x", "trailing characters after final separator")]
    [InlineData("\\Microsoft\\\n", "trailing newline ($ would accept it)")]
    [InlineData("\\Micro\nsoft\\", "embedded newline")]
    [InlineData("\\Microsoft\\\0", "NUL byte")]
    [InlineData("\uFF3CMicrosoft\uFF3C", "fullwidth backslash look-alike")]
    [InlineData("\\M\u0456crosoft\\", "non-ASCII look-alike letter")]
    [InlineData(@"\Micro$oft\", "shell metacharacter")]
    [InlineData(@"\a;b\", "semicolon")]
    public void MalformedOrDangerousTaskPathsAreRejected(string path, string why)
    {
        var d = Validate(path);
        Assert.False(d.Allowed, $"'{why}' was accepted");
    }

    [Fact]
    public void NullValueIsRejectedWithoutThrowing()
    {
        var d = Validate(null);
        Assert.False(d.Allowed);
    }

    [Fact]
    public void MaximumLengthBoundaryIsEnforced()
    {
        var atLimit = @"\" + new string('a', 258) + @"\";       // 260 characters
        var overLimit = @"\" + new string('a', 259) + @"\";      // 261 characters
        Assert.Equal(260, atLimit.Length);

        Assert.True(Validate(atLimit).Allowed);
        var d = Validate(overLimit);
        Assert.False(d.Allowed);
        Assert.Equal("parameter-too-long:TaskPath", d.Reason);
    }

    [Fact]
    public void ShippedManifestDeniesEveryTaskPathUntilAnAdministratorScopesIt()
    {
        var tool = _fx.Tool(ToolId);
        // Default scope list is empty on purpose: write tools are deny-all until scoped.
        var supplied = new Dictionary<string, string>
        {
            ["TaskPath"] = @"\Microsoft\Windows\", ["TaskName"] = "MyTask", ["Enabled"] = "true"
        };
        var d = _validator.Validate(tool, supplied);
        Assert.False(d.Allowed);
        Assert.Equal("resource-not-allowlisted:TaskPath", d.Reason);
    }

    [Fact]
    public void ScopedTaskPathIsAcceptedOnlyOnExactMatch()
    {
        var tool = _fx.Tool(ToolId);
        tool.ResourceAllowlist["TaskPath"] = new List<string> { @"\MyApp\" };

        Dictionary<string, string> Call(string path) =>
            new() { ["TaskPath"] = path, ["TaskName"] = "MyTask", ["Enabled"] = "true" };

        Assert.True(_validator.Validate(tool, Call(@"\MyApp\")).Allowed);
        Assert.False(_validator.Validate(tool, Call(@"\MyApp\Sub\")).Allowed);
        Assert.False(_validator.Validate(tool, Call(@"\")).Allowed);
    }

    [Fact]
    public void ManifestPatternAndWrapperPatternAreIdentical()
    {
        var wrapper = File.ReadAllText(RepoPaths.Combine("jea", "modules", "Set-BrokerScheduledTaskState.psm1"));
        var m = Regex.Match(wrapper, @"\[ValidatePattern\('(?<p>[^']*)'\)\]\s*\[string\]\s*\$TaskPath");
        Assert.True(m.Success, "TaskPath ValidatePattern not found in wrapper");

        // PowerShell single-quoted literals do not process backslashes, so the wrapper text
        // is the regex itself and must equal the decoded manifest pattern.
        Assert.Equal(Pattern(), m.Groups["p"].Value);
    }

    [Fact]
    public void GeneratedRoleCapabilityCarriesTheSamePattern()
    {
        var outDir = Path.Combine(Path.GetTempPath(), $"mcp-gen-{Guid.NewGuid():N}");
        try
        {
            new JeaConfigGenerator(outDir).GenerateAll(new[] { _fx.Tool(ToolId) });
            var psrc = File.ReadAllText(Path.Combine(outDir, "SetScheduledTaskState.psrc"));
            Assert.Contains($"Name = 'TaskPath'; ValidatePattern = '{Pattern().Replace("'", "''")}'", psrc);
        }
        finally
        {
            try { Directory.Delete(outDir, true); } catch { }
        }
    }

    [Fact]
    public void PatternIsAnchoredAtBothEndsWithAbsoluteEndOfString()
    {
        // \z (not $) so a trailing newline cannot slip through the JEA-side ValidatePattern,
        // which uses the same .NET regex engine.
        Assert.StartsWith("^", Pattern());
        Assert.EndsWith(@"\z", Pattern());
        Assert.False(Regex.IsMatch("\\Microsoft\\\n", Pattern(), RegexOptions.CultureInvariant));
    }
}
