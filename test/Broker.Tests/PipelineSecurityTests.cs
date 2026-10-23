using System.Text.Json;
using Broker.Audit;
using Broker.Core;
using Broker.Host;
using Broker.JeaExecution;
using Broker.Policy;
using Broker.Registry;
using Broker.Transport;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Broker.Tests;

file sealed class AllowSignatures : ISignatureVerifier { public bool Verify(ToolManifest tool) => true; }
file sealed class DenySignatures : ISignatureVerifier { public bool Verify(ToolManifest tool) => false; }
file sealed class ThrowingSignatures : ISignatureVerifier { public bool Verify(ToolManifest tool) => throw new InvalidOperationException("verifier crashed"); }

internal sealed class DelegateExecutor : IJeaExecutor
{
    private readonly Func<ToolManifest, IReadOnlyDictionary<string, object>, Task<JeaInvocationResult>> _fn;
    public int Calls;
    public DelegateExecutor(Func<ToolManifest, IReadOnlyDictionary<string, object>, Task<JeaInvocationResult>> fn) => _fn = fn;
    public Task<JeaInvocationResult> InvokeAsync(ToolManifest tool, IReadOnlyDictionary<string, object> argv, CallContext context, CancellationToken ct)
    {
        Interlocked.Increment(ref Calls);
        return _fn(tool, argv);
    }
}

/// <summary>
/// Drives the real BrokerPipeline with real policy/registry components. The executor is a spy, so
/// "the request never reached PowerShell" is an assertion on Calls == 0, not an assumption.
/// </summary>
public sealed class PipelineSecurityTests : IDisposable
{
    private const string Caller = "S-1-5-21-CALLER";
    private const string Approver = "S-1-5-21-APPROVER";

    private readonly string _manifestPath = Path.Combine(Path.GetTempPath(), $"mcp-pipe-{Guid.NewGuid():N}.json");
    private readonly string _corrPath = Path.Combine(Path.GetTempPath(), $"mcp-pipe-corr-{Guid.NewGuid():N}.log");
    private readonly SpyJeaExecutor _spy = new();
    private readonly TaintTracker _taint = new(300);

    public PipelineSecurityTests()
    {
        object Tool(string id, string tier, object[] parameters, string[]? untrusted = null,
            string[]? masked = null, bool? requiresElicitation = null)
        {
            var d = new Dictionary<string, object?>
            {
                ["toolId"] = id,
                ["displayName"] = id,
                ["server"] = new { serverId = "s", path = @"C:\fake\s.psm1", signatureThumbprint = new string('A', 40) },
                ["riskTier"] = tier,
                ["jeaMapping"] = new { endpointName = tier == "read" ? "ep.read" : "ep.write", roleCapabilityName = "rc-" + id, cmdlet = "Do-Thing", moduleName = "Do-Thing", accessGroup = "G" },
                ["parameters"] = parameters,
                ["untrustedInputSources"] = untrusted ?? Array.Empty<string>(),
                ["maskedFields"] = masked ?? Array.Empty<string>()
            };
            if (requiresElicitation is not null) d["requiresElicitation"] = requiresElicitation;
            return d;
        }

        var tools = new[]
        {
            Tool("read-plain", "read", Array.Empty<object>()),
            Tool("read-int", "read", new object[] { new { name = "DaysBack", type = "int", required = false, allowlist = new { range = new { min = 1, max = 30 } } } }),
            Tool("read-bomb", "read", new object[] { new { name = "P", type = "string", required = true, allowlist = new { regexPattern = "^(a+)+$", maxLength = 100 } } }),
            Tool("read-masked", "read", Array.Empty<object>(), masked: new[] { "Secret" }),
            Tool("read-untrusted", "read", Array.Empty<object>(), untrusted: new[] { "ad-attribute" }),
            Tool("write-svc", "write", new object[] { new { name = "Name", type = "string", required = true, allowlist = new { regexPattern = "^[A-Za-z]+$" } } }, requiresElicitation: false),
            Tool("write-untrusted", "write", Array.Empty<object>(), untrusted: new[] { "ad-attribute" })
        };
        File.WriteAllText(_manifestPath, JsonSerializer.Serialize(new { tools }));
    }

    private BrokerPipeline Build(
        ISignatureVerifier? sig = null, RateLimiter? rate = null, TaintTracker? taint = null,
        AmsiScanner? amsi = null, ConsentEngine? consent = null, IJeaExecutor? jea = null, string? corrPath = null)
        => new(new ManifestStore(_manifestPath, NullLogger<ManifestStore>.Instance),
            sig ?? new AllowSignatures(), new ParameterValidator(), new UntrustedSourceGate(),
            rate ?? new RateLimiter(1000, 1000, 0),
            amsi ?? new AmsiScanner(NullLogger<AmsiScanner>.Instance, AmsiMode.BestEffort, new FakeAmsiApi()),
            consent ?? new ConsentEngine(requireDistinctApprover: true, approverSids: new[] { Approver }),
            new ArgvBuilder(), jea ?? _spy, taint ?? _taint, new CorrelationLog(corrPath ?? _corrPath),
            NullLogger<BrokerPipeline>.Instance);

    private static ToolCallRequest Call(string tool, params (string k, string v)[] ps) =>
        new() { ToolId = tool, Parameters = ps.ToDictionary(p => p.k, p => p.v) };

    private static Task<ToolCallResult> Run(BrokerPipeline p, ToolCallRequest r, ElicitationChannel? e = null, string caller = Caller)
        => p.DispatchAsync(r, CallContext.New(caller, r.ToolId), e ?? Throwing(), CancellationToken.None);

    private static ElicitationChannel Throwing() =>
        new((_, _) => throw new InvalidOperationException("elicitation reached: an earlier gate should have rejected"));

    private static ElicitationChannel Approving(string approver = Approver) =>
        new((c, _) => Task.FromResult(new ElicitationReply(c.CorrelationId, c.ParamHash, true, approver, c.ToolId)));

    // ------------------------------------------------------------------ denials never reach PowerShell

    [Fact]
    public async Task UnknownToolIsRejectedWithoutExecution()
    {
        var r = await Run(Build(), Call("nope"));
        Assert.Equal("unknown-or-revoked-tool", r.RejectReason);
        Assert.Equal(0, _spy.Calls);
    }

    [Fact]
    public async Task FailedSignatureIsRejectedWithoutExecution()
    {
        var r = await Run(Build(sig: new DenySignatures()), Call("read-plain"));
        Assert.Equal("signature-verification-failed", r.RejectReason);
        Assert.Equal(0, _spy.Calls);
    }

    [Theory]
    [InlineData("1.5")]
    [InlineData("NaN")]
    [InlineData("1e1")]
    [InlineData("99999999999")]
    [InlineData("abc")]
    [InlineData("")]
    [InlineData("0")]
    [InlineData("31")]
    public async Task InvalidIntegerIsRejectedBeforeAnyExecution(string value)
    {
        var r = await Run(Build(), Call("read-int", ("DaysBack", value)));
        Assert.False(r.Success);
        Assert.StartsWith("parameter-", r.RejectReason);
        Assert.Equal(0, _spy.Calls);
    }

    [Fact]
    public async Task ValidIntegerReachesTheExecutorAsATypedInt()
    {
        var r = await Run(Build(), Call("read-int", ("DaysBack", "7")));
        Assert.True(r.Success, r.RejectReason);
        Assert.Equal(7, Assert.IsType<int>(_spy.Invocations.Single().Argv["DaysBack"]));
    }

    [Theory]
    [InlineData("bad name")]
    [InlineData("Spooler\n")]
    [InlineData("Spooler;Stop-Service")]
    public async Task ParameterViolationIsRejectedBeforeApprovalIsEvenRequested(string name)
    {
        var r = await Run(Build(), Call("write-svc", ("Name", name)), Throwing());
        Assert.StartsWith("parameter-", r.RejectReason);
        Assert.Equal(0, _spy.Calls);
    }

    [Fact]
    public async Task TaintedCallerCannotDriveAWriteEvenWithAnApproval()
    {
        var taint = new TaintTracker(300);
        taint.MarkTainted(Caller);

        var r = await Run(Build(taint: taint), Call("write-svc", ("Name", "Spooler")), Approving());

        Assert.Equal("caller-tainted", r.RejectReason);
        Assert.Equal(0, _spy.Calls);
    }

    [Fact]
    public async Task UntrustedSourceWriteToolCannotBeApprovedIntoRunning()
    {
        var r = await Run(Build(), Call("write-untrusted"), Approving());
        Assert.Equal("untrusted-source-cannot-mutate", r.RejectReason);
        Assert.Equal(0, _spy.Calls);
    }

    [Fact]
    public async Task RateLimitedCallIsRejectedWithoutExecution()
    {
        var rate = new RateLimiter(callsPerMinute: 1, destructivePerHour: 10, globalCallsPerMinute: 0);
        var p = Build(rate: rate);

        Assert.True((await Run(p, Call("read-plain"))).Success);
        var second = await Run(p, Call("read-plain"));

        Assert.Equal("rate-limit-exceeded", second.RejectReason);
        Assert.Equal(1, _spy.Calls);
    }

    [Fact]
    public async Task GlobalRateLimitStopsDifferentCallersCollectively()
    {
        var p = Build(rate: new RateLimiter(100, 10, globalCallsPerMinute: 2));
        Assert.True((await Run(p, Call("read-plain"), caller: "A")).Success);
        Assert.True((await Run(p, Call("read-plain"), caller: "B")).Success);

        var third = await Run(p, Call("read-plain"), caller: "C");
        Assert.Equal("global-rate-limit-exceeded", third.RejectReason);
        Assert.Equal(2, _spy.Calls);
    }

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    public async Task BlankCallerIdentityIsRejectedWithoutExecution(string caller)
    {
        var r = await Run(Build(), Call("read-plain"), caller: caller);
        Assert.Equal("caller-identity-missing", r.RejectReason);
        Assert.Equal(0, _spy.Calls);
    }

    // ------------------------------------------------------------------ approval is bound to the operation

    [Fact]
    public async Task WriteToolWithRequiresElicitationFalseStillAsksForApproval()
    {
        int asked = 0;
        var channel = new ElicitationChannel((c, _) =>
        {
            Interlocked.Increment(ref asked);
            return Task.FromResult(new ElicitationReply(c.CorrelationId, c.ParamHash, true, Approver, c.ToolId));
        });

        var r = await Run(Build(), Call("write-svc", ("Name", "Spooler")), channel);

        Assert.True(r.Success, r.RejectReason);
        Assert.Equal(1, asked);
        Assert.Equal(1, _spy.Calls);
    }

    [Fact]
    public async Task ApprovalRequestCarriesAnOperationHashBoundToToolCallerAndParameters()
    {
        ElicitationContext? seen = null;
        var channel = new ElicitationChannel((c, _) =>
        {
            seen = c;
            return Task.FromResult(new ElicitationReply(c.CorrelationId, c.ParamHash, true, Approver, c.ToolId));
        });

        await Run(Build(), Call("write-svc", ("Name", "Spooler")), channel);

        Assert.NotNull(seen);
        Assert.Equal(ConsentEngine.HashOperation("write-svc", Caller,
            new Dictionary<string, string> { ["Name"] = "Spooler" }), seen!.ParamHash);
    }

    [Fact]
    public async Task ApprovalRequestCarriesTheParametersSoAHumanCanActuallyReviewThem()
    {
        ElicitationContext? seen = null;
        var channel = new ElicitationChannel((c, _) =>
        {
            seen = c;
            return Task.FromResult(new ElicitationReply(c.CorrelationId, c.ParamHash, true, Approver, c.ToolId));
        });

        await Run(Build(), Call("write-svc", ("Name", "Spooler")), channel);

        Assert.NotNull(seen!.Parameters);
        Assert.Equal("Spooler", seen.Parameters!["Name"]);
        // The shown parameters are exactly the ones that were hashed and will be executed.
        Assert.Equal(seen.ParamHash, ConsentEngine.HashOperation(seen.ToolId, seen.CallerSid, seen.Parameters));
    }

    [Fact]
    public async Task ApprovalNamingAnotherToolIsRejected()
    {
        var channel = new ElicitationChannel((c, _) =>
            Task.FromResult(new ElicitationReply(c.CorrelationId, c.ParamHash, true, Approver, "some-other-tool")));

        var r = await Run(Build(), Call("write-svc", ("Name", "Spooler")), channel);

        Assert.Equal("elicitation-tool-mismatch", r.RejectReason);
        Assert.Equal(0, _spy.Calls);
    }

    [Fact]
    public async Task ApprovalWithoutAToolIdentityIsRejected()
    {
        var channel = new ElicitationChannel((c, _) =>
            Task.FromResult(new ElicitationReply(c.CorrelationId, c.ParamHash, true, Approver)));

        var r = await Run(Build(), Call("write-svc", ("Name", "Spooler")), channel);

        Assert.Equal("elicitation-tool-mismatch", r.RejectReason);
        Assert.Equal(0, _spy.Calls);
    }

    [Fact]
    public async Task ApprovalForDifferentParametersIsRejected()
    {
        var otherHash = ConsentEngine.HashOperation("write-svc", Caller, new Dictionary<string, string> { ["Name"] = "BITS" });
        var channel = new ElicitationChannel((c, _) =>
            Task.FromResult(new ElicitationReply(c.CorrelationId, otherHash, true, Approver, c.ToolId)));

        var r = await Run(Build(), Call("write-svc", ("Name", "Spooler")), channel);

        Assert.Equal("elicitation-param-mismatch", r.RejectReason);
        Assert.Equal(0, _spy.Calls);
    }

    [Fact]
    public async Task ApprovalForAnotherCorrelationIsRejected()
    {
        var channel = new ElicitationChannel((c, _) =>
            Task.FromResult(new ElicitationReply("an-old-correlation", c.ParamHash, true, Approver, c.ToolId)));

        var r = await Run(Build(), Call("write-svc", ("Name", "Spooler")), channel);

        Assert.Equal("elicitation-correlation-mismatch", r.RejectReason);
        Assert.Equal(0, _spy.Calls);
    }

    [Fact]
    public async Task CallerCannotApproveItsOwnWrite()
    {
        var r = await Run(Build(consent: new ConsentEngine(false)), Call("write-svc", ("Name", "Spooler")), Approving(approver: Caller));
        Assert.Equal("self-approval-forbidden", r.RejectReason);
        Assert.Equal(0, _spy.Calls);
    }

    [Fact]
    public async Task ApproverOutsideTheAllowlistIsRejected()
    {
        var r = await Run(Build(), Call("write-svc", ("Name", "Spooler")), Approving(approver: "S-1-5-21-STRANGER"));
        Assert.Equal("approver-not-authorized", r.RejectReason);
        Assert.Equal(0, _spy.Calls);
    }

    [Fact]
    public async Task DeniedApprovalIsRejected()
    {
        var channel = new ElicitationChannel((c, _) =>
            Task.FromResult(new ElicitationReply(c.CorrelationId, c.ParamHash, false, Approver, c.ToolId)));
        var r = await Run(Build(), Call("write-svc", ("Name", "Spooler")), channel);
        Assert.Equal("elicitation-denied", r.RejectReason);
        Assert.Equal(0, _spy.Calls);
    }

    [Fact]
    public async Task ElicitationChannelFailureIsARejectNotAnException()
    {
        var channel = new ElicitationChannel((_, _) => throw new IOException("approval pipe broke"));
        var r = await Run(Build(), Call("write-svc", ("Name", "Spooler")), channel);
        Assert.Equal("elicitation-failed", r.RejectReason);
        Assert.Equal(0, _spy.Calls);
    }

    [Fact]
    public async Task ApprovedCallIsHeldIfTheCallerBecomesTaintedWhileWaitingForApproval()
    {
        var taint = new TaintTracker(300);
        // While the human decides, the same caller finishes an untrusted-source read.
        var channel = new ElicitationChannel((c, _) =>
        {
            taint.MarkTainted(Caller);
            return Task.FromResult(new ElicitationReply(c.CorrelationId, c.ParamHash, true, Approver, c.ToolId));
        });

        var r = await Run(Build(taint: taint), Call("write-svc", ("Name", "Spooler")), channel);

        Assert.Equal("caller-tainted", r.RejectReason);
        Assert.Equal(0, _spy.Calls);
    }

    // ------------------------------------------------------------------ taint creation

    [Fact]
    public async Task UntrustedReadTaintsTheCallerBeforeTheExecutorIsInvoked()
    {
        bool taintedDuringExecution = false;
        var jea = new DelegateExecutor((_, _) =>
        {
            taintedDuringExecution = _taint.IsTainted(Caller);
            var now = DateTimeOffset.UtcNow;
            return Task.FromResult(new JeaInvocationResult(true, 0, "[]", 1, now, now));
        });

        await Run(Build(jea: jea), Call("read-untrusted"));

        Assert.True(taintedDuringExecution, "an in-flight untrusted read must already block a concurrent write");
        Assert.True(_taint.IsTainted(Caller));
    }

    [Fact]
    public async Task UntrustedReadTaintsEvenWhenTheExecutionFails()
    {
        var jea = new DelegateExecutor((_, _) =>
        {
            var now = DateTimeOffset.UtcNow;
            return Task.FromResult(new JeaInvocationResult(false, 1, "{}", 1, now, now));
        });

        var r = await Run(Build(jea: jea), Call("read-untrusted"));

        Assert.False(r.Success);
        Assert.True(_taint.IsTainted(Caller));
    }

    [Fact]
    public async Task TaintingOneCallerDoesNotBlockAnother()
    {
        await Run(Build(), Call("read-untrusted"), caller: "ALICE");
        var r = await Run(Build(), Call("write-svc", ("Name", "Spooler")), Approving(), caller: "BOB");
        Assert.True(r.Success, r.RejectReason);
    }

    [Fact]
    public async Task PlainReadDoesNotTaint()
    {
        await Run(Build(), Call("read-plain"));
        Assert.False(_taint.IsTainted(Caller));
    }

    // ------------------------------------------------------------------ gate order

    [Fact]
    public async Task TaintIsCheckedBeforeParameters()
    {
        var taint = new TaintTracker(300);
        taint.MarkTainted(Caller);
        var r = await Run(Build(taint: taint), Call("write-svc", ("Name", "bad name")));
        Assert.Equal("caller-tainted", r.RejectReason);
    }

    [Fact]
    public async Task ParametersAreCheckedBeforeTheUntrustedSourceGate()
    {
        var r = await Run(Build(), Call("write-untrusted", ("bogus", "x")));
        Assert.StartsWith("unknown-parameter", r.RejectReason);
    }

    [Fact]
    public async Task SignatureIsCheckedBeforeEverythingElse()
    {
        var taint = new TaintTracker(300);
        taint.MarkTainted(Caller);
        var r = await Run(Build(sig: new DenySignatures(), taint: taint), Call("write-untrusted", ("bogus", "x")));
        Assert.Equal("signature-verification-failed", r.RejectReason);
    }

    // ------------------------------------------------------------------ AMSI is supplementary

    [Fact]
    public async Task AmsiDetectionBlocksExecution()
    {
        var amsi = new AmsiScanner(NullLogger<AmsiScanner>.Instance, AmsiMode.BestEffort, new FakeAmsiApi { ScanResult = 32768 });
        var r = await Run(Build(amsi: amsi), Call("read-int", ("DaysBack", "5")));
        Assert.Equal("amsi-detected-malicious-content", r.RejectReason);
        Assert.Equal(0, _spy.Calls);
    }

    [Fact]
    public async Task StrictAmsiDeniesWhenNoProviderIsAvailable()
    {
        var amsi = new AmsiScanner(NullLogger<AmsiScanner>.Instance, AmsiMode.Strict, new FakeAmsiApi { InitializeThrows = new DllNotFoundException() });
        var r = await Run(Build(amsi: amsi), Call("read-int", ("DaysBack", "5")));
        Assert.Equal("amsi-unavailable", r.RejectReason);
        Assert.Equal(0, _spy.Calls);
    }

    [Fact]
    public async Task AnUnavailableAmsiNeverBypassesTheOtherGates()
    {
        var unavailable = new AmsiScanner(NullLogger<AmsiScanner>.Instance, AmsiMode.BestEffort, new FakeAmsiApi { InitializeThrows = new DllNotFoundException() });
        var taint = new TaintTracker(300);
        taint.MarkTainted(Caller);

        Assert.Equal("caller-tainted",
            (await Run(Build(amsi: unavailable, taint: taint), Call("write-svc", ("Name", "Spooler")), Approving())).RejectReason);
        Assert.Equal("untrusted-source-cannot-mutate",
            (await Run(Build(amsi: unavailable), Call("write-untrusted"), Approving())).RejectReason);
        Assert.StartsWith("parameter-",
            (await Run(Build(amsi: unavailable), Call("read-int", ("DaysBack", "NaN")))).RejectReason);
        Assert.Equal(0, _spy.Calls);
    }

    [Fact]
    public async Task AmsiIsNeverConsultedForARequestThatFailedValidation()
    {
        var api = new FakeAmsiApi();
        var amsi = new AmsiScanner(NullLogger<AmsiScanner>.Instance, AmsiMode.BestEffort, api);

        await Run(Build(amsi: amsi), Call("read-int", ("DaysBack", "NaN")));

        Assert.Equal(0, api.ScanCalls);
    }

    // ------------------------------------------------------------------ mandatory gates fail closed

    [Fact]
    public async Task ASignatureVerifierThatThrowsRejectsInsteadOfThrowing()
    {
        var r = await Run(Build(sig: new ThrowingSignatures()), Call("read-plain"));
        Assert.Equal("signature-verification-failed", r.RejectReason);
        Assert.Equal(0, _spy.Calls);
    }

    [Fact]
    public async Task RegexTimeoutInValidationRejectsInsteadOfThrowing()
    {
        // Catastrophic backtracking trips the validator's 100 ms regex timeout.
        var evil = new string('a', 40) + "!";
        var r = await Run(Build(), Call("read-bomb", ("P", evil)));
        Assert.Equal("parameter-validation-error", r.RejectReason);
        Assert.Equal(0, _spy.Calls);
    }

    [Fact]
    public async Task AnExecutorThatThrowsIsARejectNotAnException()
    {
        var jea = new DelegateExecutor((_, _) => throw new InvalidOperationException("session exploded"));
        var r = await Run(Build(jea: jea), Call("read-plain"));
        Assert.False(r.Success);
        Assert.Equal("jea-execution-error", r.RejectReason);
        Assert.DoesNotContain("exploded", r.RejectReason);
    }

    [Fact]
    public async Task ExecutorFailureReasonIsClientSafe()
    {
        var jea = new DelegateExecutor((_, _) =>
        {
            var now = DateTimeOffset.UtcNow;
            return Task.FromResult(new JeaInvocationResult(false, 5, "{}", 1, now, now, "capacity-exceeded"));
        });
        var r = await Run(Build(jea: jea), Call("read-plain"));
        Assert.Equal("capacity-exceeded", r.RejectReason);
    }

    // ------------------------------------------------------------------ output masking

    private DelegateExecutor Returning(string payload) => new((_, _) =>
    {
        var now = DateTimeOffset.UtcNow;
        return Task.FromResult(new JeaInvocationResult(true, 0, payload, 1, now, now));
    });

    [Fact]
    public async Task MaskedFieldsAreRedactedAtAnyDepth()
    {
        var r = await Run(Build(jea: Returning("""[{"Name":"a","Secret":"hunter2","Nested":{"secret":"x","Keep":1}}]""")), Call("read-masked"));
        Assert.True(r.Success);
        Assert.DoesNotContain("hunter2", r.PayloadJson);
        Assert.DoesNotContain("\"x\"", r.PayloadJson);
        Assert.Contains("***MASKED***", r.PayloadJson);
        Assert.Contains("\"Keep\":1", r.PayloadJson);
    }

    [Fact]
    public async Task MaskingKeepsLargeIntegersExact()
    {
        var r = await Run(Build(jea: Returning("""[{"Secret":"s","SizeBytes":9007199254740993}]""")), Call("read-masked"));
        Assert.Contains("9007199254740993", r.PayloadJson);
    }

    [Theory]
    [InlineData("not json at all")]
    [InlineData("{\"Secret\": ")]
    [InlineData("")]
    public async Task MaskingFailureRejectsInsteadOfReturningTheRawPayload(string payload)
    {
        var r = await Run(Build(jea: Returning(payload)), Call("read-masked"));
        Assert.False(r.Success);
        Assert.Equal("output-masking-failed", r.RejectReason);
        Assert.Null(r.PayloadJson);
    }

    [Fact]
    public async Task ToolWithoutMaskedFieldsReturnsThePayloadUntouched()
    {
        var r = await Run(Build(jea: Returning("[{\"a\":1}]")), Call("read-plain"));
        Assert.Equal("[{\"a\":1}]", r.PayloadJson);
    }

    // ------------------------------------------------------------------ audit sink failures

    [Fact]
    public async Task CorrelationLogFailureDoesNotTurnACompletedCallIntoAnError()
    {
        // The log path is an existing directory, so every Append throws.
        var dirAsFile = Path.Combine(Path.GetTempPath(), $"mcp-corr-dir-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dirAsFile);
        try
        {
            var r = await Run(Build(corrPath: dirAsFile), Call("read-plain"));
            Assert.True(r.Success, r.RejectReason);
            Assert.Equal(1, _spy.Calls);
        }
        finally { Directory.Delete(dirAsFile); }
    }

    public void Dispose()
    {
        try { File.Delete(_manifestPath); } catch { }
        try { File.Delete(_corrPath); } catch { }
    }
}
