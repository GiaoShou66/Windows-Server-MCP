using System.Text.Json;
using Broker.Audit;
using Broker.Core;
using Broker.Host;
using Broker.JeaExecution;
using Broker.Policy;
using Broker.Registry;
using Broker.Transport;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Broker.Tests;

file sealed class FakeSignatureVerifier : ISignatureVerifier
{
    private readonly bool _result;
    public FakeSignatureVerifier(bool result) => _result = result;
    public bool Verify(ToolManifest tool) => _result;
}

/// <summary>
/// Exercises the real 8-gate BrokerPipeline (manifest lookup -> signature -> taint ->
/// params -> untrusted-source -> rate limit -> elicitation -> JEA invoke) end to end,
/// using real Policy/Registry components and a temp-file manifest. Every scenario here
/// is rejected before gate 8, so JeaEndpointClient is constructed but never invoked —
/// no live JEA session is needed. This is the first coverage of BrokerPipeline itself,
/// which previously had zero tests despite being the component that ties every other
/// fix (taint, distinct approver, signature re-check, rate limit) together.
/// </summary>
public sealed class BrokerPipelineTests : IDisposable
{
    private readonly string _manifestPath;
    private readonly string _correlationLogPath;

    public BrokerPipelineTests()
    {
        _manifestPath = Path.Combine(Path.GetTempPath(), $"mcp-test-manifest-{Guid.NewGuid():N}.json");
        _correlationLogPath = Path.Combine(Path.GetTempPath(), $"mcp-test-correlation-{Guid.NewGuid():N}.log");

        var manifest = new
        {
            tools = new object[]
            {
                new
                {
                    toolId = "read-tool",
                    displayName = "Read Tool",
                    server = new { serverId = "s1", path = @"C:\fake\s1.psm1", signatureThumbprint = new string('A', 40) },
                    riskTier = "read",
                    jeaMapping = new { endpointName = "ep.read", roleCapabilityName = "rc.read", cmdlet = "Get-Thing", moduleName = "Get-Thing", accessGroup = "G" },
                    parameters = Array.Empty<object>(),
                    untrustedInputSources = Array.Empty<string>(),
                    maskedFields = Array.Empty<string>()
                },
                new
                {
                    toolId = "untrusted-read-tool",
                    displayName = "Untrusted Read Tool",
                    server = new { serverId = "s2", path = @"C:\fake\s2.psm1", signatureThumbprint = new string('A', 40) },
                    riskTier = "read",
                    jeaMapping = new { endpointName = "ep.read", roleCapabilityName = "rc.read2", cmdlet = "Get-Other", moduleName = "Get-Other", accessGroup = "G" },
                    parameters = Array.Empty<object>(),
                    untrustedInputSources = new[] { "ad-attribute" },
                    maskedFields = Array.Empty<string>()
                },
                new
                {
                    toolId = "write-tool",
                    displayName = "Write Tool",
                    server = new { serverId = "s3", path = @"C:\fake\s3.psm1", signatureThumbprint = new string('A', 40) },
                    riskTier = "write",
                    requiresElicitation = false,
                    jeaMapping = new { endpointName = "ep.write", roleCapabilityName = "rc.write", cmdlet = "Set-Thing", moduleName = "Set-Thing", accessGroup = "G" },
                    parameters = Array.Empty<object>(),
                    untrustedInputSources = Array.Empty<string>(),
                    maskedFields = Array.Empty<string>()
                },
                new
                {
                    toolId = "write-untrusted-tool",
                    displayName = "Write Untrusted Tool",
                    server = new { serverId = "s4", path = @"C:\fake\s4.psm1", signatureThumbprint = new string('A', 40) },
                    riskTier = "write",
                    requiresElicitation = false,
                    jeaMapping = new { endpointName = "ep.write", roleCapabilityName = "rc.write2", cmdlet = "Set-Other", moduleName = "Set-Other", accessGroup = "G" },
                    parameters = Array.Empty<object>(),
                    untrustedInputSources = new[] { "ad-attribute" },
                    maskedFields = Array.Empty<string>()
                },
                new
                {
                    toolId = "write-tool-elicited",
                    displayName = "Write Tool Requiring Elicitation",
                    server = new { serverId = "s5", path = @"C:\fake\s5.psm1", signatureThumbprint = new string('A', 40) },
                    riskTier = "write",
                    requiresElicitation = true,
                    jeaMapping = new { endpointName = "ep.write", roleCapabilityName = "rc.write3", cmdlet = "Set-Elicited", moduleName = "Set-Elicited", accessGroup = "G" },
                    parameters = Array.Empty<object>(),
                    untrustedInputSources = Array.Empty<string>(),
                    maskedFields = Array.Empty<string>()
                }
            }
        };

        File.WriteAllText(_manifestPath, JsonSerializer.Serialize(manifest));
    }

    private BrokerPipeline BuildPipeline(ISignatureVerifier verifier, RateLimiter? rateLimiter = null, TaintTracker? taint = null, Microsoft.Extensions.Configuration.IConfiguration? config = null)
    {
        var manifestStore = new ManifestStore(_manifestPath, NullLogger<ManifestStore>.Instance);
        return new BrokerPipeline(
            manifestStore, verifier, new ParameterValidator(), new UntrustedSourceGate(),
            rateLimiter ?? new RateLimiter(callsPerMinute: 1000, destructivePerHour: 1000),
            new AmsiScanner(NullLogger<AmsiScanner>.Instance), new ConsentEngine(),
            new ArgvBuilder(), new JeaEndpointClient(NullLogger<JeaEndpointClient>.Instance),
            taint ?? new TaintTracker(windowSeconds: 300),
            new CorrelationLog(_correlationLogPath), NullLogger<BrokerPipeline>.Instance,
            config);
    }

    private static ToolCallRequest Call(string toolId) => new() { ToolId = toolId, Parameters = new() };

    [Fact]
    public async Task UnknownToolRejected()
    {
        var pipeline = BuildPipeline(new FakeSignatureVerifier(true));
        var ctx = CallContext.New("CALLER", "nonexistent");
        var result = await pipeline.DispatchAsync(Call("nonexistent"), ctx, DummyElicitation(), CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal("unknown-or-revoked-tool", result.RejectReason);
    }

    [Fact]
    public async Task SignatureFailureRejectsBeforeAnyOtherGate()
    {
        var pipeline = BuildPipeline(new FakeSignatureVerifier(false));
        var ctx = CallContext.New("CALLER", "read-tool");
        var result = await pipeline.DispatchAsync(Call("read-tool"), ctx, DummyElicitation(), CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal("signature-verification-failed", result.RejectReason);
    }

    [Fact]
    public async Task UntrustedWriteToolRejectedWithNoElicitationOverride()
    {
        var pipeline = BuildPipeline(new FakeSignatureVerifier(true));
        var ctx = CallContext.New("CALLER-A", "write-untrusted-tool");

        // ThrowingElicitation would throw if ever invoked — proves the hard gate fires
        // before elicitation is reached, with no override path.
        var result = await pipeline.DispatchAsync(Call("write-untrusted-tool"), ctx, ThrowingElicitation(), CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal("untrusted-source-cannot-mutate", result.RejectReason);
    }

    [Fact]
    public async Task TaintedCallerBlockedFromWriteTool()
    {
        var taint = new TaintTracker(windowSeconds: 300);
        taint.MarkTainted("TAINTED-CALLER");
        var pipeline = BuildPipeline(new FakeSignatureVerifier(true), taint: taint);

        var ctx = CallContext.New("TAINTED-CALLER", "write-tool");
        var result = await pipeline.DispatchAsync(Call("write-tool"), ctx, ThrowingElicitation(), CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal("caller-tainted", result.RejectReason);
    }

    [Fact]
    public async Task UntaintedCallerPassesTaintGateForWriteTool()
    {
        // Elicitation for a write tool is now unconditional (monotonic), so this uses an
        // approving channel rather than ThrowingElicitation: the point of the test is the
        // taint gate, not the approval gate. The call proceeds past taint and approval and
        // fails only at JEA invoke (fake server path doesn't exist) — proving the taint gate
        // is caller-scoped, not tool-scoped: an untainted caller is never blocked by it.
        var pipeline = BuildPipeline(new FakeSignatureVerifier(true));
        var ctx = CallContext.New("CLEAN-CALLER", "write-tool");
        var result = await pipeline.DispatchAsync(Call("write-tool"), ctx, DummyElicitation(), CancellationToken.None);

        Assert.NotEqual("caller-tainted", result.RejectReason);
        Assert.NotEqual("caller-tainted-after-approval", result.RejectReason);
    }

    /// <summary>
    /// Elicitation is monotonic: requiresElicitation:false cannot disable approval for a
    /// write-tier tool. A manifest typo must not silently remove the human-approval control.
    /// </summary>
    [Fact]
    public async Task RequiresElicitationFalseCannotDisableApprovalForWriteTool()
    {
        var pipeline = BuildPipeline(new FakeSignatureVerifier(true));
        var ctx = CallContext.New("CALLER", "write-tool"); // fixture sets requiresElicitation: false

        // ThrowingElicitation fires only if the approval gate is reached — which it must be.
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => pipeline.DispatchAsync(Call("write-tool"), ctx, ThrowingElicitation(), CancellationToken.None));

        Assert.Contains("Elicitation reached", ex.Message);
    }

    [Fact]
    public async Task RateLimitBlocksAfterBudgetExhausted()
    {
        var limiter = new RateLimiter(callsPerMinute: 2, destructivePerHour: 1000);
        var pipeline = BuildPipeline(new FakeSignatureVerifier(true), rateLimiter: limiter);
        var ctx1 = CallContext.New("RL-CALLER", "read-tool");
        var ctx2 = CallContext.New("RL-CALLER", "read-tool");
        var ctx3 = CallContext.New("RL-CALLER", "read-tool");

        await pipeline.DispatchAsync(Call("read-tool"), ctx1, ThrowingElicitation(), CancellationToken.None);
        await pipeline.DispatchAsync(Call("read-tool"), ctx2, ThrowingElicitation(), CancellationToken.None);
        var third = await pipeline.DispatchAsync(Call("read-tool"), ctx3, ThrowingElicitation(), CancellationToken.None);

        Assert.False(third.Success);
        Assert.Equal("rate-limit-exceeded", third.RejectReason);
    }

    [Fact]
    public async Task UnknownParameterRejectedBeforeUntrustedGate()
    {
        var pipeline = BuildPipeline(new FakeSignatureVerifier(true));
        var ctx = CallContext.New("CALLER", "read-tool");
        var request = new ToolCallRequest { ToolId = "read-tool", Parameters = new() { ["bogus"] = "x" } };

        var result = await pipeline.DispatchAsync(request, ctx, ThrowingElicitation(), CancellationToken.None);

        Assert.False(result.Success);
        Assert.StartsWith("unknown-parameter", result.RejectReason);
    }

    /// <summary>
    /// First real exercise of the elicitation gate for a write tool. All prior write-tool
    /// tests used requiresElicitation: false to isolate earlier gates; this fixture has it
    /// true, matching how the first real write tools (set-scheduled-task-state etc.) are
    /// actually configured in the shipped manifest.
    /// </summary>
    [Fact]
    public async Task ElicitedWriteToolProceedsPastElicitationWhenApproved()
    {
        var pipeline = BuildPipeline(new FakeSignatureVerifier(true));
        var ctx = CallContext.New("CALLER", "write-tool-elicited");

        var result = await pipeline.DispatchAsync(Call("write-tool-elicited"), ctx, DummyElicitation(), CancellationToken.None);

        // Fails at JEA invoke (fake server path doesn't exist) — proving it got PAST the
        // elicitation gate, not rejected AT it.
        Assert.False(result.Success);
        Assert.NotEqual("elicitation-denied", result.RejectReason);
        Assert.NotEqual("elicitation-timeout-or-disconnect", result.RejectReason);
        Assert.Equal("jea-execution-error", result.RejectReason);
    }

    [Fact]
    public async Task ElicitedWriteToolRejectedWhenElicitationDenied()
    {
        var pipeline = BuildPipeline(new FakeSignatureVerifier(true));
        var ctx = CallContext.New("CALLER", "write-tool-elicited");

        var result = await pipeline.DispatchAsync(Call("write-tool-elicited"), ctx, DenyingElicitation(), CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal("elicitation-denied", result.RejectReason);
    }

    [Fact]
    public async Task MutatingToolFailsFastWhenDistinctApproverIsDisabled()
    {
        var config = new Microsoft.Extensions.Configuration.ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Elicitation:RequireDistinctApprover"] = "false"
        }).Build();

        var pipeline = BuildPipeline(new FakeSignatureVerifier(true), config: config);
        var ctx = CallContext.New("CALLER", "write-tool-elicited");

        // Uses ThrowingElicitation() to prove it fails fast BEFORE invoking any elicitation channel
        var result = await pipeline.DispatchAsync(Call("write-tool-elicited"), ctx, ThrowingElicitation(), CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal("distinct-approver-required", result.RejectReason);
    }

    private static ElicitationChannel DummyElicitation() =>
        new((ctx, ct) => Task.FromResult(new ElicitationReply(
            ctx.CorrelationId, ctx.ParamHash, true, "APPROVER-SID", ctx.ToolId)));

    private static ElicitationChannel DenyingElicitation() =>
        new((ctx, ct) => Task.FromResult(new ElicitationReply(ctx.CorrelationId, ctx.ParamHash, false, "APPROVER-SID")));

    private static ElicitationChannel ThrowingElicitation() =>
        new((ctx, ct) => throw new InvalidOperationException(
            "Elicitation reached — a gate that should have rejected earlier did not."));

    public void Dispose()
    {
        try { File.Delete(_manifestPath); } catch { }
        try { File.Delete(_correlationLogPath); } catch { }
    }
}
