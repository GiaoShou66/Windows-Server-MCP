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
    public void HappyPathAllows()
    {
        var c = new ConsentEngine();
        var h = ConsentEngine.HashParameters(new Dictionary<string, string> { ["a"] = "1" });
        var d = c.Verify("corr", h, "caller", "corr", h, approved: true, decidedBySid: "caller");
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
