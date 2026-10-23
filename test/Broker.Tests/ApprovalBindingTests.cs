using System.Reflection;
using Broker.Core;
using Broker.Policy;
using Broker.Registry;
using Broker.Transport;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Broker.Tests;

public class ConsentEngineToolBindingTests
{
    private static readonly Dictionary<string, string> Params = new() { ["ServiceName"] = "Spooler", ["Action"] = "Stop" };

    private static string Hash(string tool = "set-windows-service-state", string caller = "CALLER", Dictionary<string, string>? p = null)
        => ConsentEngine.HashOperation(tool, caller, p ?? Params);

    private static ConsentEngine Distinct() => new(requireDistinctApprover: true, approverSids: new[] { "APPROVER" });

    [Fact]
    public void VerifyHasNoOptionalParametersAndNoOverloads()
    {
        var methods = typeof(ConsentEngine).GetMethods(BindingFlags.Public | BindingFlags.Instance)
            .Where(m => m.Name == nameof(ConsentEngine.Verify)).ToArray();

        var single = Assert.Single(methods);
        Assert.All(single.GetParameters(), p => Assert.False(p.IsOptional, $"parameter {p.Name} is optional"));
        Assert.Contains(single.GetParameters(), p => p.Name == "expectedToolId");
        Assert.Contains(single.GetParameters(), p => p.Name == "replyToolId");
    }

    [Fact]
    public void ApprovalForToolACannotAuthorizeToolB()
    {
        var h = Hash();
        var d = Distinct().Verify("corr", h, "CALLER", "corr", h, true, "APPROVER",
            expectedToolId: "set-windows-service-state", replyToolId: "set-firewall-rule-enabled");

        Assert.False(d.Allowed);
        Assert.Equal("elicitation-tool-mismatch", d.Reason);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void MissingExpectedToolIdentityIsRejected(string? expected)
    {
        var h = Hash();
        var d = Distinct().Verify("corr", h, "CALLER", "corr", h, true, "APPROVER",
            expectedToolId: expected!, replyToolId: "set-windows-service-state");

        Assert.False(d.Allowed);
        Assert.Equal("elicitation-tool-invalid", d.Reason);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("SET-WINDOWS-SERVICE-STATE")]
    [InlineData("set-windows-service-state ")]
    public void MissingOrNonIdenticalReplyToolIdentityIsRejected(string? reply)
    {
        var h = Hash();
        var d = Distinct().Verify("corr", h, "CALLER", "corr", h, true, "APPROVER",
            expectedToolId: "set-windows-service-state", replyToolId: reply!);

        Assert.False(d.Allowed);
        Assert.Equal("elicitation-tool-mismatch", d.Reason);
    }

    [Fact]
    public void MatchingToolAndOperationIsAllowed()
    {
        var h = Hash();
        var d = Distinct().Verify("corr", h, "CALLER", "corr", h, true, "APPROVER",
            "set-windows-service-state", "set-windows-service-state");
        Assert.True(d.Allowed, d.Reason);
    }

    [Fact]
    public void ApprovalIsBoundToTheTarget()
    {
        var approvedForSpooler = Hash(p: new() { ["ServiceName"] = "Spooler", ["Action"] = "Stop" });
        var executingAgainst = Hash(p: new() { ["ServiceName"] = "BITS", ["Action"] = "Stop" });

        var d = Distinct().Verify("corr", executingAgainst, "CALLER", "corr", approvedForSpooler, true, "APPROVER",
            "set-windows-service-state", "set-windows-service-state");

        Assert.False(d.Allowed);
        Assert.Equal("elicitation-param-mismatch", d.Reason);
    }

    [Fact]
    public void OperationHashBindsToolAndCallerAsWellAsParameters()
    {
        var baseline = Hash();
        Assert.NotEqual(baseline, Hash(tool: "set-firewall-rule-enabled"));
        Assert.NotEqual(baseline, Hash(caller: "OTHER-CALLER"));
        Assert.NotEqual(baseline, Hash(p: new() { ["ServiceName"] = "BITS", ["Action"] = "Stop" }));
        Assert.Equal(baseline, Hash(p: new() { ["Action"] = "Stop", ["ServiceName"] = "Spooler" }));
    }

    [Fact]
    public void ApprovalCannotBeReplayedAgainstAnotherCorrelation()
    {
        var h = Hash();
        var d = Distinct().Verify("corr-NEW", h, "CALLER", "corr-OLD", h, true, "APPROVER",
            "set-windows-service-state", "set-windows-service-state");

        Assert.False(d.Allowed);
        Assert.Equal("elicitation-correlation-mismatch", d.Reason);
    }

    [Theory]
    [InlineData("", "APPROVER", "caller-identity-missing")]
    [InlineData("CALLER", "", "approver-identity-missing")]
    [InlineData("   ", "APPROVER", "caller-identity-missing")]
    public void AbsentIdentitiesAreRejectedEvenWhenEverythingElseMatches(string caller, string approver, string reason)
    {
        var h = Hash();
        // Both identities empty would otherwise look "equal" or "unlisted"; either way it must be
        // an explicit identity failure, never an implicit pass.
        var d = new ConsentEngine().Verify("corr", h, caller, "corr", h, true, approver,
            "set-windows-service-state", "set-windows-service-state");

        Assert.False(d.Allowed);
        Assert.Equal(reason, d.Reason);
    }

    [Fact]
    public void SelfApprovalIsForbiddenEvenWhenCallerSidIsAlsoAnApprover()
    {
        var engine = new ConsentEngine(true, new[] { "CALLER" });
        var h = Hash();
        var d = engine.Verify("corr", h, "CALLER", "corr", h, true, "caller",
            "set-windows-service-state", "set-windows-service-state");

        Assert.False(d.Allowed);
        Assert.Equal("self-approval-forbidden", d.Reason);
    }
}

public class ElicitationRouterBindingTests
{
    private static ElicitationRouter NewRouter() => new(NullLogger<ElicitationRouter>.Instance);

    [Fact]
    public async Task ApprovalCannotBeReusedAfterItResolvedOnce()
    {
        var router = NewRouter();
        var ctx = new ElicitationContext("corr-1", "tool-a", "CALLER", "hash-1");
        var pending = router.RequestAsync(ctx, TimeSpan.FromSeconds(5), CancellationToken.None);

        var reply = new ElicitationReply("corr-1", "hash-1", true, "APPROVER", "tool-a");
        Assert.True(router.TryResolve("corr-1", reply));
        await pending.WaitAsync(TimeSpan.FromSeconds(2));

        Assert.False(router.TryResolve("corr-1", reply));
    }

    [Fact]
    public async Task ApprovalForOneRequestCannotResolveAnother()
    {
        var router = NewRouter();
        var a = router.RequestAsync(new ElicitationContext("corr-A", "tool-a", "CALLER", "hash-A"), TimeSpan.FromSeconds(5), CancellationToken.None);
        var b = router.RequestAsync(new ElicitationContext("corr-B", "tool-a", "CALLER", "hash-B"), TimeSpan.FromSeconds(5), CancellationToken.None);

        // A reply that names B's correlation but carries A's hash must not resolve B.
        Assert.False(router.TryResolve("corr-B", new ElicitationReply("corr-B", "hash-A", true, "APPROVER", "tool-a")));
        // A reply that names a different tool must not resolve either.
        Assert.False(router.TryResolve("corr-A", new ElicitationReply("corr-A", "hash-A", true, "APPROVER", "tool-b")));
        // Smuggling A's correlation inside B's lookup key must not resolve.
        Assert.False(router.TryResolve("corr-B", new ElicitationReply("corr-A", "hash-B", true, "APPROVER", "tool-a")));

        Assert.True(router.TryResolve("corr-A", new ElicitationReply("corr-A", "hash-A", true, "APPROVER", "tool-a")));
        Assert.True(router.TryResolve("corr-B", new ElicitationReply("corr-B", "hash-B", true, "APPROVER", "tool-a")));
        await Task.WhenAll(a, b).WaitAsync(TimeSpan.FromSeconds(2));
    }

    [Fact]
    public async Task ExpiredApprovalIsRejected()
    {
        var router = NewRouter();
        var pending = router.RequestAsync(
            new ElicitationContext("corr-X", "tool-a", "CALLER", "hash-X"), TimeSpan.FromMilliseconds(60), CancellationToken.None);

        await Task.Delay(150);

        Assert.False(router.TryResolve("corr-X", new ElicitationReply("corr-X", "hash-X", true, "APPROVER", "tool-a")));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
    }

    [Fact]
    public async Task ConcurrentRepliesResolveExactlyOnce()
    {
        var router = NewRouter();
        var pending = router.RequestAsync(
            new ElicitationContext("corr-C", "tool-a", "CALLER", "hash-C"), TimeSpan.FromSeconds(5), CancellationToken.None);

        var wins = 0;
        await Task.WhenAll(Enumerable.Range(0, 64).Select(i => Task.Run(() =>
        {
            if (router.TryResolve("corr-C", new ElicitationReply("corr-C", "hash-C", true, $"APPROVER-{i}", "tool-a")))
                Interlocked.Increment(ref wins);
        })));

        Assert.Equal(1, wins);
        await pending.WaitAsync(TimeSpan.FromSeconds(2));
    }
}
