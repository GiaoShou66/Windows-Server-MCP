using System.Text.Json;
using System.Text.RegularExpressions;
using Broker.Core;
using Broker.Host;
using Broker.Registry;
using Xunit;

namespace Broker.Tests;

/// <summary>
/// Static analysis of the checked-in PowerShell wrappers and manifest. These tests do NOT execute
/// the wrappers or observe real Windows Server output (no AD, DNS, DHCP, Hyper-V, ... in CI); they
/// check that what the code is written to return matches the documented inventory and the masking policy.
/// </summary>
public sealed class OutputSchemaInventoryTests : IClassFixture<ShippedManifestFixture>
{
    // Outputs that are sensitive identifiers but are deliberately returned unmasked because the
    // tool's purpose is to show them. Anything else classed security-identifier must be masked.
    private static readonly HashSet<string> IntentionallyUnmaskedIdentifiers = new(StringComparer.Ordinal)
    {
        "list-user-rights-assignments.AssignedTo",       // the SIDs/accounts ARE the answer
        "list-ad-organizational-units.DistinguishedName" // an OU's DN is its identity; GPO links need it
    };

    // Masked in the manifest although the wrapper never emits them: defense in depth only.
    private static readonly HashSet<string> DefenseInDepthMasks = new(StringComparer.Ordinal)
    {
        "list-bitlocker-volumes.KeyProtectorId",
        "list-bitlocker-volumes.RecoveryPassword"
    };

    private readonly ShippedManifestFixture _fx;
    private readonly JsonElement _inventory;

    public OutputSchemaInventoryTests(ShippedManifestFixture fx)
    {
        _fx = fx;
        _inventory = JsonDocument.Parse(File.ReadAllText(RepoPaths.Combine("docs", "read-tier-output-schemas.json"))).RootElement.Clone();
    }

    private IEnumerable<ToolManifest> ReadTools => _fx.Store.All.Where(t => t.RiskTier == RiskTier.Read);
    private JsonElement Tools => _inventory.GetProperty("tools");

    private static string WrapperPath(ToolManifest t) => RepoPaths.Combine("jea", "modules", t.JeaMapping.ModuleName + ".psm1");

    internal static string StripComments(string psm1)
    {
        var noBlocks = Regex.Replace(psm1, @"<#.*?#>", "", RegexOptions.Singleline);
        return string.Join("\n", noBlocks.Split('\n').Where(l => !l.TrimStart().StartsWith('#')));
    }

    internal static List<string> ProjectedFields(string psm1)
    {
        var fields = new List<string>();
        foreach (Match block in Regex.Matches(StripComments(psm1), @"\[pscustomobject\]@\{\s*\n(.*?)\n\s*\}", RegexOptions.Singleline))
            foreach (var line in block.Groups[1].Value.Split('\n'))
            {
                var k = Regex.Match(line, @"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=");
                if (k.Success && !fields.Contains(k.Groups[1].Value)) fields.Add(k.Groups[1].Value);
            }
        return fields;
    }

    [Fact]
    public void EveryReadToolHasAnInventoryEntryAndNothingElseDoes()
    {
        var inventoried = Tools.EnumerateObject().Select(p => p.Name).OrderBy(x => x).ToArray();
        var shipped = ReadTools.Select(t => t.ToolId).OrderBy(x => x).ToArray();
        Assert.Equal(shipped, inventoried);
    }

    [Fact]
    public void InventoryFieldsAreExactlyTheFieldsTheWrapperProjects()
    {
        foreach (var t in ReadTools)
        {
            var declared = Tools.GetProperty(t.ToolId).GetProperty("fields").EnumerateObject().Select(p => p.Name).OrderBy(x => x).ToArray();
            var actual = ProjectedFields(File.ReadAllText(WrapperPath(t))).OrderBy(x => x).ToArray();

            Assert.True(actual.Length > 0, $"{t.ToolId}: wrapper has no explicit [pscustomobject] projection");
            Assert.Equal(actual, declared);
        }
    }

    [Fact]
    public void InventoryCmdletMatchesTheManifest()
    {
        foreach (var t in ReadTools)
            Assert.Equal(t.JeaMapping.Cmdlet, Tools.GetProperty(t.ToolId).GetProperty("cmdlet").GetString());
    }

    [Fact]
    public void EveryClassIsDefinedAndNoOutputFieldIsASecret()
    {
        var classes = _inventory.GetProperty("classes").EnumerateObject().Select(p => p.Name).ToHashSet();
        Assert.Contains("secret", classes);

        foreach (var tool in Tools.EnumerateObject())
            foreach (var f in tool.Value.GetProperty("fields").EnumerateObject())
            {
                Assert.Contains(f.Value.GetString()!, classes);
                Assert.NotEqual("secret", f.Value.GetString());
            }
    }

    [Fact]
    public void EverySecurityIdentifierFieldIsMaskedUnlessItsPurposeIsToShowIt()
    {
        foreach (var t in ReadTools)
            foreach (var f in Tools.GetProperty(t.ToolId).GetProperty("fields").EnumerateObject())
            {
                if (f.Value.GetString() != "security-identifier") continue;
                if (IntentionallyUnmaskedIdentifiers.Contains($"{t.ToolId}.{f.Name}")) continue;

                Assert.Contains(f.Name, t.MaskedFields, StringComparer.OrdinalIgnoreCase);
            }
    }

    [Fact]
    public void EveryManifestMaskNamesAnEmittedFieldOrIsADeclaredDefenseInDepthMask()
    {
        foreach (var t in ReadTools)
        {
            var emitted = Tools.GetProperty(t.ToolId).GetProperty("fields").EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var mask in t.MaskedFields)
                Assert.True(emitted.Contains(mask) || DefenseInDepthMasks.Contains($"{t.ToolId}.{mask}"),
                    $"{t.ToolId} masks '{mask}', which the wrapper never emits and which is not a declared defense-in-depth mask");
        }
    }

    [Fact]
    public void ReadToolsWithAttackerInfluenceableTextAreEitherTaggedOrCarryAnExplicitDecision()
    {
        foreach (var t in ReadTools)
        {
            var entry = Tools.GetProperty(t.ToolId);
            if (!entry.TryGetProperty("untrustedText", out var text) || text.GetArrayLength() == 0) continue;

            var fields = entry.GetProperty("fields").EnumerateObject().Select(p => p.Name).ToHashSet();
            Assert.All(text.EnumerateArray(), f => Assert.Contains(f.GetString()!, fields));

            if (t.UntrustedInputSources.Count > 0) continue;   // tagged: reading it taints the caller

            Assert.True(entry.TryGetProperty("taintDecision", out var decision) && decision.GetString() == "accepted-untagged",
                $"{t.ToolId} returns free text others can author but is neither tagged untrusted nor explicitly accepted");
            Assert.False(string.IsNullOrWhiteSpace(entry.GetProperty("taintDecisionReason").GetString()));
        }
    }

    [Fact]
    public void EveryToolTaggedUntrustedReallyHasInfluenceableTextOrIsADocumentedAdditionalCase()
    {
        // Tagged tools whose output is numeric policy values only are tagged defensively; list them
        // so a removal of the tag is a conscious edit rather than a silent drift.
        var taggedWithoutText = ReadTools
            .Where(t => t.UntrustedInputSources.Count > 0)
            .Where(t => !Tools.GetProperty(t.ToolId).TryGetProperty("untrustedText", out var u) || u.GetArrayLength() == 0)
            .Select(t => t.ToolId).OrderBy(x => x).ToArray();

        Assert.Equal(new[] { "get-domain-password-policy", "summarize-transcript-logs" }, taggedWithoutText);
    }

    [Fact]
    public void MaskingRedactsEveryMaskedFieldOfEveryShippedToolAndKeepsTheRest()
    {
        foreach (var t in ReadTools.Where(t => t.MaskedFields.Count > 0))
        {
            var row = Tools.GetProperty(t.ToolId).GetProperty("fields").EnumerateObject()
                .ToDictionary(p => p.Name, p => $"SENTINEL-{p.Name}");
            foreach (var extra in t.MaskedFields) row.TryAdd(extra, $"SENTINEL-{extra}");   // defense-in-depth names too

            var payload = JsonSerializer.Serialize(new[] { row });
            Assert.True(BrokerPipeline.TryMask(payload, t.MaskedFields, out var masked), t.ToolId);

            foreach (var kv in row)
            {
                bool shouldMask = t.MaskedFields.Contains(kv.Key, StringComparer.OrdinalIgnoreCase);
                if (shouldMask) Assert.DoesNotContain(kv.Value, masked);
                else Assert.Contains(kv.Value, masked);
            }
        }
    }

    [Fact]
    public void MarkdownInventoryMentionsEveryReadTool()
    {
        var md = File.ReadAllText(RepoPaths.Combine("docs", "read-tier-output-inventory.md"));
        foreach (var t in ReadTools) Assert.Contains($"`{t.ToolId}`", md);
    }
}

/// <summary>Hygiene rules applied to EVERY wrapper (read and write), read as source text.</summary>
public sealed class WrapperHygieneTests : IClassFixture<ShippedManifestFixture>
{
    private readonly ShippedManifestFixture _fx;
    public WrapperHygieneTests(ShippedManifestFixture fx) => _fx = fx;

    private IEnumerable<(ToolManifest tool, string code)> Wrappers() =>
        _fx.Store.All.Select(t => (t, OutputSchemaInventoryTests.StripComments(
            File.ReadAllText(RepoPaths.Combine("jea", "modules", t.JeaMapping.ModuleName + ".psm1")))));

    [Fact]
    public void EveryManifestToolHasAWrapperThatDefinesAndExportsExactlyItsCmdlet()
    {
        foreach (var (t, code) in Wrappers())
        {
            Assert.Matches($@"(?m)^function {Regex.Escape(t.JeaMapping.Cmdlet)}\s*\{{", code);
            Assert.Matches($@"(?m)^Export-ModuleMember -Function {Regex.Escape(t.JeaMapping.Cmdlet)}\s*$", code);
            Assert.Single(Regex.Matches(code, @"(?m)^function \S+"));
        }
    }

    [Fact]
    public void WrappersNeverShapeOutputByWildcardOrDumpRawObjects()
    {
        var forbidden = new[]
        {
            @"Select-Object\s+(-Property\s+)?\*", @"-Property\s+\*", @"\bFormat-(List|Table|Custom|Wide)\b",
            @"\bOut-String\b", @"\bConvertTo-(Json|Csv|Xml|Html)\b", @"\bExport-(Clixml|Csv)\b",
            @"\bWrite-Host\b", @"\bOut-File\b", @"\bSet-Content\b"
        };
        foreach (var (t, code) in Wrappers())
            foreach (var pattern in forbidden)
                Assert.False(Regex.IsMatch(code, pattern), $"{t.JeaMapping.ModuleName} matches /{pattern}/");
    }

    [Fact]
    public void NoWrapperReadsOrEmitsCredentialOrKeyMaterial()
    {
        var secretish = @"\.(RecoveryPassword|KeyProtector\w*|SecurePassword|PrivateKey|PfxData|Credential\w*)\b|" +
                        @"\bGet-Credential\b|\bConvertFrom-SecureString\b|\bGetNetworkCredential\b|\bUnprotect-\w+|\bExport-PfxCertificate\b";
        foreach (var (t, code) in Wrappers())
            Assert.False(Regex.IsMatch(code, secretish), $"{t.JeaMapping.ModuleName} touches credential or key material");
    }

    [Fact]
    public void NoWrapperExecutesDynamicCodeOrReachesTheNetwork()
    {
        var forbidden = new[]
        {
            @"\b(Invoke-Expression|iex)\b", @"\bAdd-Type\b", @"\bStart-Process\b", @"\bInvoke-Command\b",
            @"\bInvoke-(WebRequest|RestMethod|Item)\b", @"\bNew-PSSession\b", @"\bEnter-PSSession\b",
            @"\[System\.Reflection", @"\[Reflection\.", @"System\.Net\.(WebClient|Sockets)", @"\bSet-ExecutionPolicy\b",
            @"\bDownloadString\b", @"-EncodedCommand\b"
        };
        foreach (var (t, code) in Wrappers())
            foreach (var pattern in forbidden)
                Assert.False(Regex.IsMatch(code, pattern), $"{t.JeaMapping.ModuleName} matches /{pattern}/");
    }

    [Fact]
    public void ExternalExecutablesInAWrapperAreExactlyThoseTheManifestAllowlists()
    {
        foreach (var (t, code) in Wrappers())
        {
            // "& name.exe" with a literal name; a call through a variable or expression is refused below.
            var used = Regex.Matches(code, @"&\s+([A-Za-z0-9_.\-]+\.exe)\b").Select(m => m.Groups[1].Value.ToLowerInvariant()).Distinct().OrderBy(x => x).ToArray();
            var allowed = (t.JeaMapping.ExternalCommands ?? new()).Select(x => x.ToLowerInvariant()).OrderBy(x => x).ToArray();

            Assert.Equal(allowed, used);
            Assert.False(Regex.IsMatch(code, @"&\s+(\$|\(|\{|""|')"),
                $"{t.JeaMapping.ModuleName} invokes a command through a variable or expression");
        }
    }

    [Fact]
    public void EveryWrapperUsesStrictModeAndCmdletBinding()
    {
        foreach (var t in _fx.Store.All)
        {
            var raw = File.ReadAllText(RepoPaths.Combine("jea", "modules", t.JeaMapping.ModuleName + ".psm1"));
            Assert.Contains("Set-StrictMode -Version Latest", raw);
            Assert.Contains("[CmdletBinding()]", raw);
        }
    }
}

public sealed class NetworkControllerProjectionTests
{
    [Fact]
    public void NodeIsProjectedToNamesRatherThanPassedThroughAsAnObjectGraph()
    {
        var code = OutputSchemaInventoryTests.StripComments(
            File.ReadAllText(RepoPaths.Combine("jea", "modules", "Get-BrokerNetworkControllerConfig.psm1")));

        Assert.Contains("Node              = @($nc.Node | ForEach-Object { [string] $_.Name })", code);
        Assert.DoesNotMatch(@"Node\s*=\s*\$nc\.Node\s*$", code);
    }
}
