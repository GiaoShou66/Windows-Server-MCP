using System.Text;
using Broker.Core;
using Broker.Policy;
using Broker.Registry;
using Broker.Transport;
using Xunit;

namespace Broker.Tests;

file static class Build
{
    public static ToolManifest Tool(RiskTier tier, string[]? untrusted = null, params ToolParameter[] ps) => new()
    {
        ToolId = "t",
        RiskTierRaw = tier switch
        {
            RiskTier.Write => "write",
            RiskTier.Destructive => "destructive",
            _ => "read"
        },
        Parameters = ps.ToList(),
        UntrustedInputSources = (untrusted ?? Array.Empty<string>()).ToList()
    };

    public static ToolParameter Param(string name, ParameterAllowlist allow, bool required = false, string type = "string")
        => new() { Name = name, Type = type, Required = required, Allowlist = allow };
}

public class ParameterValidatorTests
{
    private readonly ParameterValidator _v = new();

    [Fact]
    public void UnknownParameterRejected()
    {
        var tool = Build.Tool(RiskTier.Read);
        var d = _v.Validate(tool, new Dictionary<string, string> { ["x"] = "1" });
        Assert.False(d.Allowed);
        Assert.StartsWith("unknown-parameter", d.Reason);
    }

    [Fact]
    public void MissingRequiredRejected()
    {
        var tool = Build.Tool(RiskTier.Read, null,
            Build.Param("n", new ParameterAllowlist { RegexPattern = "^[a-z]+$" }, required: true));
        var d = _v.Validate(tool, new Dictionary<string, string>());
        Assert.False(d.Allowed);
        Assert.StartsWith("missing-required-parameter", d.Reason);
    }

    [Fact]
    public void ResourceOutsideAllowlistRejected()
    {
        var tool = Build.Tool(RiskTier.Write, null,
            Build.Param("ServiceName", new ParameterAllowlist { RegexPattern = "^[A-Za-z]+$" }, required: true));
        tool.ResourceAllowlist["ServiceName"] = new List<string> { "AllowedService" };

        var decision = _v.Validate(tool, new Dictionary<string, string>
        {
            ["ServiceName"] = "OtherService"
        });

        Assert.False(decision.Allowed);
        Assert.Equal("resource-not-allowlisted:ServiceName", decision.Reason);
    }

    [Theory]
    [InlineData("abc", true)]
    [InlineData("ABC", false)]
    public void RegexEnforced(string value, bool ok)
    {
        var tool = Build.Tool(RiskTier.Read, null,
            Build.Param("n", new ParameterAllowlist { RegexPattern = "^[a-z]+$" }));
        var d = _v.Validate(tool, new Dictionary<string, string> { ["n"] = value });
        Assert.Equal(ok, d.Allowed);
    }

    [Theory]
    [InlineData("b", true)]
    [InlineData("c", false)]
    public void EnumEnforced(string value, bool ok)
    {
        var tool = Build.Tool(RiskTier.Read, null,
            Build.Param("n", new ParameterAllowlist { EnumValues = new() { "a", "b" } }));
        var d = _v.Validate(tool, new Dictionary<string, string> { ["n"] = value });
        Assert.Equal(ok, d.Allowed);
    }

    private static ToolManifest BoolTool(params string[] enumValues) => Build.Tool(RiskTier.Write, null,
        Build.Param("Enabled", new ParameterAllowlist { EnumValues = enumValues.ToList() }, required: true, type: "bool"));

    /// <summary>
    /// A bool parameter matches its enum case-insensitively, so "True"/"False" from a client
    /// that stringifies booleans is accepted instead of failing parameter-not-in-enum.
    /// </summary>
    [Theory]
    [InlineData("true", true)]
    [InlineData("false", true)]
    [InlineData("True", true)]
    [InlineData("FALSE", true)]
    [InlineData("tRuE", true)]
    [InlineData("1", false)]
    [InlineData("0", false)]
    [InlineData("yes", false)]
    [InlineData("", false)]
    public void BoolEnumIsCaseInsensitive(string value, bool ok)
    {
        var d = _v.Validate(BoolTool("true", "false"), new Dictionary<string, string> { ["Enabled"] = value });
        Assert.Equal(ok, d.Allowed);
        if (!ok) Assert.Equal("parameter-not-in-enum:Enabled", d.Reason);
    }

    /// <summary>
    /// Case is the ONLY thing relaxed. bool.Parse itself trims whitespace and NUL, so the
    /// enum check is what keeps padded values out; look-alike code points must not fold to
    /// ASCII either (U+017F LONG S upper-cases to 'S', U+0131 DOTLESS I to 'I').
    /// </summary>
    [Fact]
    public void BoolEnumRejectsPaddedAndLookAlikeValues()
    {
        var tool = BoolTool("true", "false");
        var hostile = new[]
        {
            " true", "true ", "\ttrue", "true\n", "true\r\n", "true\0", "\0false",
            "falſe",                    // LATIN SMALL LETTER LONG S
            "FALſE",
            "ｔｒｕｅ",      // fullwidth "true"
            "truе",                     // CYRILLIC SMALL LETTER IE
            "true,false", "true;false"
        };

        foreach (var value in hostile)
        {
            var d = _v.Validate(tool, new Dictionary<string, string> { ["Enabled"] = value });
            Assert.False(d.Allowed, $"'{value.Replace("\0", "\\0")}' must not pass a bool enum");
            Assert.Equal("parameter-not-in-enum:Enabled", d.Reason);
        }
    }

    /// <summary>
    /// Case-insensitivity must not widen the allowed SET: a bool pinned to "false" (a
    /// disable-only tool) still refuses "true" in every casing.
    /// </summary>
    [Fact]
    public void BoolCaseInsensitivityDoesNotWidenARestrictedEnum()
    {
        var tool = BoolTool("false");
        Assert.True(_v.Validate(tool, new Dictionary<string, string> { ["Enabled"] = "FALSE" }).Allowed);
        Assert.False(_v.Validate(tool, new Dictionary<string, string> { ["Enabled"] = "true" }).Allowed);
        Assert.False(_v.Validate(tool, new Dictionary<string, string> { ["Enabled"] = "True" }).Allowed);
    }

    /// <summary>Only bool is relaxed; string/enum members remain exact-case identifiers.</summary>
    [Theory]
    [InlineData("string")]
    [InlineData("enum")]
    public void NonBoolEnumStaysCaseSensitive(string type)
    {
        var tool = Build.Tool(RiskTier.Write, null,
            Build.Param("Action", new ParameterAllowlist { EnumValues = new() { "Start", "Stop", "true" } }, type: type));

        Assert.True(_v.Validate(tool, new Dictionary<string, string> { ["Action"] = "Start" }).Allowed);
        Assert.False(_v.Validate(tool, new Dictionary<string, string> { ["Action"] = "start" }).Allowed);
        Assert.False(_v.Validate(tool, new Dictionary<string, string> { ["Action"] = "STOP" }).Allowed);
        Assert.False(_v.Validate(tool, new Dictionary<string, string> { ["Action"] = "True" }).Allowed);
    }

    /// <summary>
    /// Validator and ArgvBuilder must agree: every casing the validator accepts converts to
    /// the bool the caller meant, so what the approver saw is what JEA receives.
    /// </summary>
    [Theory]
    [InlineData("true", true)]
    [InlineData("True", true)]
    [InlineData("TRUE", true)]
    [InlineData("false", false)]
    [InlineData("False", false)]
    [InlineData("fALSE", false)]
    public void ValidatedBoolConvertsToTheSameValueRegardlessOfCase(string value, bool expected)
    {
        var tool = BoolTool("true", "false");
        var supplied = new Dictionary<string, string> { ["Enabled"] = value };

        Assert.True(_v.Validate(tool, supplied).Allowed);
        Assert.Equal(expected, new ArgvBuilder().Build(tool, supplied)["Enabled"]);
    }

    private static ToolManifest LoadShippedTool(string toolId)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "mcp-broker.sln")))
            dir = dir.Parent;
        var root = dir?.FullName ?? throw new InvalidOperationException("Could not locate repo root containing mcp-broker.sln");

        var manifest = System.Text.Json.JsonSerializer.Deserialize<ManifestFile>(
            File.ReadAllText(Path.Combine(root, "policy", "manifest.json")))!;
        return manifest.Tools.Single(t => t.ToolId == toolId);
    }

    /// <summary>
    /// Root-folder scheduled tasks have TaskPath "\". The shipped pattern used to demand a
    /// leading AND a trailing backslash (two characters minimum), so the root folder failed
    /// parameter-pattern-mismatch:TaskPath. Asserted against the real manifest because the
    /// pattern lives in JSON, where the escaping is easy to get wrong.
    /// </summary>
    [Theory]
    [InlineData(@"\", true)]
    [InlineData(@"\Contoso\", true)]
    [InlineData(@"\Microsoft\Windows\Defrag\", true)]
    [InlineData("InvalidPath", false)]
    [InlineData(@"\Contoso", false)]
    [InlineData(@"Contoso\", false)]
    [InlineData(@"C:\Windows\", false)]
    [InlineData(@"\Bad*\", false)]
    [InlineData("", false)]
    public void ShippedManifestTaskPathPatternAcceptsRootFolder(string taskPath, bool matchesPattern)
    {
        var tool = LoadShippedTool("set-scheduled-task-state");

        // The shipped resourceAllowlist is deny-all until an operator scopes the tool. Scope
        // it to exactly this value so that only the pattern is under test.
        tool.ResourceAllowlist["TaskPath"] = new List<string> { taskPath };

        var d = _v.Validate(tool, new Dictionary<string, string>
        {
            ["TaskPath"] = taskPath,
            ["TaskName"] = "OneDriveSyncHealthCheck",
            ["Enabled"] = "false"
        });

        Assert.Equal(matchesPattern, d.Allowed);
        if (!matchesPattern) Assert.Equal("parameter-pattern-mismatch:TaskPath", d.Reason);
    }

    /// <summary>
    /// An anchored allowlist pattern must cover the whole value. In .NET '$' also matches
    /// before a final newline, so "name\n" used to pass "^[a-z]+$" — in the shipped manifest
    /// too, where every pattern ends in '$'.
    /// </summary>
    [Theory]
    [InlineData("abc", true)]
    [InlineData("abc\n", false)]
    [InlineData("abc\r\n", false)]
    [InlineData("\nabc", false)]
    [InlineData("ab\nc", false)]
    public void RegexMustMatchTheWholeValue(string value, bool ok)
    {
        var tool = Build.Tool(RiskTier.Read, null,
            Build.Param("n", new ParameterAllowlist { RegexPattern = "^[a-z]+$" }));
        var d = _v.Validate(tool, new Dictionary<string, string> { ["n"] = value });
        Assert.Equal(ok, d.Allowed);
        if (!ok) Assert.Equal("parameter-pattern-mismatch:n", d.Reason);
    }

    [Theory]
    [InlineData("abc", true)]
    [InlineData("abc1", false)]
    [InlineData("1abc", false)]
    public void UnanchoredRegexIsStillTreatedAsAWholeValuePattern(string value, bool ok)
    {
        var tool = Build.Tool(RiskTier.Read, null,
            Build.Param("n", new ParameterAllowlist { RegexPattern = "[a-z]+" }));
        Assert.Equal(ok, _v.Validate(tool, new Dictionary<string, string> { ["n"] = value }).Allowed);
    }

    [Theory]
    [InlineData("TaskPath", "\\\n")]
    [InlineData("TaskPath", "\\Contoso\\\n")]
    [InlineData("TaskName", "OneDriveSyncHealthCheck\n")]
    public void ShippedManifestPatternsRejectATrailingNewline(string parameter, string hostile)
    {
        var tool = LoadShippedTool("set-scheduled-task-state");
        var supplied = new Dictionary<string, string>
        {
            ["TaskPath"] = "\\",
            ["TaskName"] = "OneDriveSyncHealthCheck",
            ["Enabled"] = "false"
        };
        supplied[parameter] = hostile;

        // Scope the resource allowlist to the supplied value so only the pattern can refuse it.
        tool.ResourceAllowlist["TaskPath"] = new List<string> { supplied["TaskPath"] };

        var d = _v.Validate(tool, supplied);
        Assert.False(d.Allowed);
        Assert.Equal($"parameter-pattern-mismatch:{parameter}", d.Reason);
    }

    /// <summary>
    /// An int parameter must be plain integer text: no padding, separators, decimals or
    /// exponents. The range check used to parse as a culture-sensitive double, so "1e1"
    /// passed validation and only failed later in ArgvBuilder.
    /// </summary>
    [Theory]
    [InlineData("5", true)]
    [InlineData("+5", true)]
    [InlineData("30", true)]
    [InlineData(" 5", false)]
    [InlineData("5 ", false)]
    [InlineData("5\n", false)]
    [InlineData("5.0", false)]
    [InlineData("1e1", false)]
    [InlineData("1,0", false)]
    [InlineData("0x5", false)]
    [InlineData("NaN", false)]
    public void IntRangeAcceptsOnlyPlainIntegerText(string value, bool ok)
    {
        var tool = Build.Tool(RiskTier.Read, null,
            Build.Param("n", new ParameterAllowlist { Range = new ParamRange { Min = 1, Max = 30 } }, type: "int"));
        var d = _v.Validate(tool, new Dictionary<string, string> { ["n"] = value });
        Assert.Equal(ok, d.Allowed);
        if (!ok) Assert.Equal("parameter-not-numeric:n", d.Reason);
    }

    /// <summary>
    /// NaN compares false against every bound, so "value below min or above max" let it
    /// through any numeric range. Infinity and padded values must be refused as well.
    /// </summary>
    [Theory]
    [InlineData("1.5", true)]
    [InlineData("1e1", true)]
    [InlineData("NaN", false)]
    [InlineData("nan", false)]
    [InlineData("Infinity", false)]
    [InlineData("-Infinity", false)]
    [InlineData("1,5", false)]
    [InlineData(" 1.5", false)]
    public void NonIntRangeRejectsNaNInfinityAndPadding(string value, bool ok)
    {
        var tool = Build.Tool(RiskTier.Read, null,
            Build.Param("n", new ParameterAllowlist { Range = new ParamRange { Min = 1, Max = 30 } }, type: "string"));
        Assert.Equal(ok, _v.Validate(tool, new Dictionary<string, string> { ["n"] = value }).Allowed);
    }

    /// <summary>
    /// The same text must be the same number on every host. Under a comma-decimal culture
    /// "1,5" used to parse as 1.5 and "1.000" as 1000.
    /// </summary>
    [Fact]
    public void NumericValidationDoesNotDependOnHostCulture()
    {
        var original = System.Globalization.CultureInfo.CurrentCulture;
        try
        {
            System.Globalization.CultureInfo.CurrentCulture = new System.Globalization.CultureInfo("de-DE");

            var asString = Build.Tool(RiskTier.Read, null,
                Build.Param("n", new ParameterAllowlist { Range = new ParamRange { Min = 1, Max = 30 } }, type: "string"));
            Assert.False(_v.Validate(asString, new Dictionary<string, string> { ["n"] = "1,5" }).Allowed);
            Assert.True(_v.Validate(asString, new Dictionary<string, string> { ["n"] = "1.5" }).Allowed);

            var asInt = Build.Tool(RiskTier.Read, null,
                Build.Param("n", new ParameterAllowlist { Range = new ParamRange { Min = 1, Max = 30 } }, type: "int"));
            var supplied = new Dictionary<string, string> { ["n"] = "12" };
            Assert.True(_v.Validate(asInt, supplied).Allowed);
            Assert.Equal(12, new ArgvBuilder().Build(asInt, supplied)["n"]);
            Assert.False(_v.Validate(asInt, new Dictionary<string, string> { ["n"] = "1.000" }).Allowed);
        }
        finally
        {
            System.Globalization.CultureInfo.CurrentCulture = original;
        }
    }

    [Theory]
    [InlineData("5", true)]
    [InlineData("40", false)]
    [InlineData("x", false)]
    public void RangeEnforced(string value, bool ok)
    {
        var tool = Build.Tool(RiskTier.Read, null,
            Build.Param("n", new ParameterAllowlist { Range = new ParamRange { Min = 1, Max = 30 } }, type: "int"));
        var d = _v.Validate(tool, new Dictionary<string, string> { ["n"] = value });
        Assert.Equal(ok, d.Allowed);
    }

    [Fact]
    public void MaxLengthEnforced()
    {
        var tool = Build.Tool(RiskTier.Read, null,
            Build.Param("n", new ParameterAllowlist { MaxLength = 3 }));
        var d = _v.Validate(tool, new Dictionary<string, string> { ["n"] = "abcd" });
        Assert.False(d.Allowed);
        Assert.StartsWith("parameter-too-long", d.Reason);
    }
}

public class UntrustedSourceGateTests
{
    private readonly UntrustedSourceGate _g = new();

    [Fact]
    public void UntrustedWriteDenied()
    {
        var tool = Build.Tool(RiskTier.Write, new[] { "ad-attribute" });
        Assert.False(_g.Evaluate(tool).Allowed);
    }

    [Fact]
    public void UntrustedReadAllowed()
    {
        var tool = Build.Tool(RiskTier.Read, new[] { "ad-attribute" });
        Assert.True(_g.Evaluate(tool).Allowed);
    }

    [Fact]
    public void TrustedDestructiveAllowed()
    {
        var tool = Build.Tool(RiskTier.Destructive);
        Assert.True(_g.Evaluate(tool).Allowed);
    }
}

public class RateLimiterTests
{
    [Fact]
    public void BlocksOverGeneralLimit()
    {
        var rl = new RateLimiter(callsPerMinute: 2, destructivePerHour: 10);
        Assert.True(rl.Check("sid", RiskTier.Read).Allowed);
        Assert.True(rl.Check("sid", RiskTier.Read).Allowed);
        Assert.False(rl.Check("sid", RiskTier.Read).Allowed);
    }

    [Fact]
    public void SeparateDestructiveBudget()
    {
        var rl = new RateLimiter(callsPerMinute: 100, destructivePerHour: 1);
        Assert.True(rl.Check("sid", RiskTier.Destructive).Allowed);
        var d = rl.Check("sid", RiskTier.Destructive);
        Assert.False(d.Allowed);
        Assert.StartsWith("destructive-rate-limit", d.Reason);
    }

    /// <summary>
    /// Every write-tier call raises an approval card, so the hourly write budget bounds how
    /// many cards one caller can put in front of the approver. It is per caller and does not
    /// consume, or get consumed by, read or destructive calls.
    /// </summary>
    [Fact]
    public void SeparateWriteBudgetPerCaller()
    {
        var rl = new RateLimiter(callsPerMinute: 100, destructivePerHour: 10, writePerHour: 2);

        Assert.True(rl.Check("sid", RiskTier.Write).Allowed);
        Assert.True(rl.Check("sid", RiskTier.Write).Allowed);

        var third = rl.Check("sid", RiskTier.Write);
        Assert.False(third.Allowed);
        Assert.Equal("write-rate-limit-exceeded", third.Reason);

        Assert.True(rl.Check("sid", RiskTier.Read).Allowed);
        Assert.True(rl.Check("sid", RiskTier.Destructive).Allowed);
        Assert.True(rl.Check("other-sid", RiskTier.Write).Allowed);
    }

    [Fact]
    public void ReadCallsDoNotConsumeTheWriteBudget()
    {
        var rl = new RateLimiter(callsPerMinute: 100, destructivePerHour: 10, writePerHour: 1);

        for (int i = 0; i < 20; i++)
            Assert.True(rl.Check("sid", RiskTier.Read).Allowed);

        Assert.True(rl.Check("sid", RiskTier.Write).Allowed);
        Assert.False(rl.Check("sid", RiskTier.Write).Allowed);
    }
}

public class ConsentEngineTests
{
    [Fact]
    public void HashIsOrderIndependent()
    {
        var a = ConsentEngine.HashParameters(new Dictionary<string, string> { ["a"] = "1", ["b"] = "2" });
        var b = ConsentEngine.HashParameters(new Dictionary<string, string> { ["b"] = "2", ["a"] = "1" });
        Assert.Equal(a, b);
    }

    [Fact]
    public void DistinctApproverHappyPathAllows()
    {
        var c = new ConsentEngine(requireDistinctApprover: true, approverSids: new[] { "approver" });
        var h = ConsentEngine.HashParameters(new Dictionary<string, string> { ["a"] = "1" });
        var d = c.Verify("corr", h, "caller", "corr", h, approved: true, decidedBySid: "approver");
        Assert.True(d.Allowed);
    }

    [Fact]
    public void CorrelationMismatchDenied()
    {
        var c = new ConsentEngine();
        var h = ConsentEngine.HashParameters(new Dictionary<string, string> { ["a"] = "1" });
        Assert.False(c.Verify("corr", h, "caller", "OTHER", h, true, "caller").Allowed);
    }

    [Fact]
    public void ParamMismatchDenied()
    {
        var c = new ConsentEngine();
        var h = ConsentEngine.HashParameters(new Dictionary<string, string> { ["a"] = "1" });
        Assert.False(c.Verify("corr", h, "caller", "corr", "DEADBEEF", true, "caller").Allowed);
    }

    [Fact]
    public void NotApprovedDenied()
    {
        var c = new ConsentEngine();
        var h = ConsentEngine.HashParameters(new Dictionary<string, string>());
        Assert.False(c.Verify("corr", h, "caller", "corr", h, approved: false, "caller").Allowed);
    }

    [Fact]
    public void SelfApprovalForbiddenWhenDistinctRequired()
    {
        var c = new ConsentEngine(requireDistinctApprover: true, approverSids: new[] { "approver" });
        var h = ConsentEngine.HashParameters(new Dictionary<string, string>());
        var d = c.Verify("corr", h, "caller", "corr", h, true, decidedBySid: "caller");
        Assert.False(d.Allowed);
        Assert.Equal("self-approval-forbidden", d.Reason);
    }

    [Fact]
    public void UnlistedApproverDenied()
    {
        var c = new ConsentEngine(requireDistinctApprover: true, approverSids: new[] { "approver" });
        var h = ConsentEngine.HashParameters(new Dictionary<string, string>());
        var d = c.Verify("corr", h, "caller", "corr", h, true, decidedBySid: "stranger");
        Assert.False(d.Allowed);
        Assert.Equal("approver-not-authorized", d.Reason);
    }

    [Fact]
    public void DistinctListedApproverAllowed()
    {
        var c = new ConsentEngine(requireDistinctApprover: true, approverSids: new[] { "approver" });
        var h = ConsentEngine.HashParameters(new Dictionary<string, string>());
        Assert.True(c.Verify("corr", h, "caller", "corr", h, true, decidedBySid: "approver").Allowed);
    }
}

public class TaintTrackerTests
{
    [Fact]
    public void MarkedCallerIsTainted()
    {
        var t = new TaintTracker(windowSeconds: 300);
        Assert.False(t.IsTainted("sid"));
        t.MarkTainted("sid");
        Assert.True(t.IsTainted("sid"));
    }

    [Fact]
    public void TaintExpires()
    {
        var t = new TaintTracker(windowSeconds: 1);
        t.MarkTainted("sid");
        Thread.Sleep(1100);
        Assert.False(t.IsTainted("sid"));
    }
}

public class McpFramingTests
{
    [Fact]
    public async Task RoundTrips()
    {
        using var ms = new MemoryStream();
        await McpFraming.WriteFrameAsync(ms, "{\"hello\":\"world\"}", CancellationToken.None);
        ms.Position = 0;
        var frame = await McpFraming.ReadFrameAsync(ms, TimeSpan.FromSeconds(5), CancellationToken.None);
        Assert.Equal("{\"hello\":\"world\"}", frame);
    }

    [Fact]
    public async Task OversizeLengthRejected()
    {
        using var ms = new MemoryStream(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF });
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await McpFraming.ReadFrameAsync(ms, TimeSpan.FromSeconds(5), CancellationToken.None));
    }

    [Fact]
    public async Task EmptyStreamReturnsNull()
    {
        using var ms = new MemoryStream();
        var frame = await McpFraming.ReadFrameAsync(ms, TimeSpan.FromSeconds(5), CancellationToken.None);
        Assert.Null(frame);
    }
}
