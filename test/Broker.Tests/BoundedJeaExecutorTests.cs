using Broker.Core;
using Broker.JeaExecution;
using Broker.Registry;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Broker.Tests;

/// <summary>Inner executor whose calls block until released, recording peak concurrency.</summary>
internal sealed class GatedExecutor : IJeaExecutor
{
    private readonly object _lock = new();
    private int _current;
    public int Peak { get; private set; }
    public int Started { get; private set; }
    public int Completed;
    public readonly List<TaskCompletionSource> Gates = new();
    public readonly List<CancellationToken> Tokens = new();
    public Func<ToolManifest, JeaInvocationResult>? Result { get; set; }
    public bool Gated { get; set; } = true;
    public Exception? Throw { get; set; }

    public async Task<JeaInvocationResult> InvokeAsync(ToolManifest tool, IReadOnlyDictionary<string, object> argv, CallContext context, CancellationToken ct)
    {
        TaskCompletionSource gate;
        lock (_lock)
        {
            _current++; Started++; Peak = Math.Max(Peak, _current);
            gate = new(TaskCreationOptions.RunContinuationsAsynchronously);
            Gates.Add(gate); Tokens.Add(ct);
        }
        try
        {
            if (Throw is not null) throw Throw;
            if (Gated) await gate.Task;
            var now = DateTimeOffset.UtcNow;
            return Result?.Invoke(tool) ?? new JeaInvocationResult(true, 0, "[]", 1, now, now);
        }
        finally
        {
            lock (_lock) _current--;
            Interlocked.Increment(ref Completed);
        }
    }

    public void ReleaseAll() { lock (_lock) foreach (var g in Gates) g.TrySetResult(); }
    public void Release(int index) { lock (_lock) Gates[index].TrySetResult(); }
    public async Task WaitForStartedAsync(int n)
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (Started < n && DateTime.UtcNow < deadline) await Task.Delay(5);
        Assert.True(Started >= n, $"only {Started} of {n} calls started");
    }
}

public class BoundedJeaExecutorTests
{
    private static ToolManifest Tool(string id, string endpoint = "ep") => new()
    {
        ToolId = id,
        JeaMapping = new JeaMapping { EndpointName = endpoint, Cmdlet = "Get-X" }
    };

    private static readonly IReadOnlyDictionary<string, object> NoArgs = new Dictionary<string, object>();
    private static CallContext Ctx(string tool = "t", string sid = "S") => CallContext.New(sid, tool);

    private static BoundedJeaExecutor Build(GatedExecutor inner, Action<JeaExecutionLimitsBuilder>? tweak = null)
    {
        var b = new JeaExecutionLimitsBuilder();
        tweak?.Invoke(b);
        return new BoundedJeaExecutor(inner, b.ToLimits(), NullLogger<BoundedJeaExecutor>.Instance);
    }

    internal sealed class JeaExecutionLimitsBuilder
    {
        public int Total = 100, PerEndpoint = 100, PerTool = 100, Queue = 100, MaxResponseBytes = 512 * 1024;
        public TimeSpan QueueWait = TimeSpan.FromSeconds(5), Execution = TimeSpan.FromSeconds(30);
        public JeaExecutionLimits ToLimits() => new()
        {
            MaxConcurrentTotal = Total, MaxConcurrentPerEndpoint = PerEndpoint, MaxConcurrentPerTool = PerTool,
            MaxQueueLength = Queue, QueueWaitTimeout = QueueWait, ExecutionTimeout = Execution,
            MaxResponseBytes = MaxResponseBytes
        };
    }

    // ------------------------------------------------------------------ concurrency bounds

    [Fact]
    public async Task TotalConcurrencyNeverExceedsTheLimitAcrossManyCallerIdentities()
    {
        var inner = new GatedExecutor();
        var exec = Build(inner, b => { b.Total = 3; b.PerEndpoint = 100; b.PerTool = 100; b.Queue = 100; });

        // 40 callers, each with its own SID and tool, all arriving at once.
        var calls = Enumerable.Range(0, 40)
            .Select(i => exec.InvokeAsync(Tool($"tool-{i}", $"ep-{i % 5}"), NoArgs, Ctx($"tool-{i}", $"SID-{i}"), CancellationToken.None))
            .ToArray();

        await inner.WaitForStartedAsync(3);
        await Task.Delay(100);
        Assert.Equal(3, inner.Started);
        Assert.Equal(3, exec.RunningCount);

        // Drain: release everything as it starts.
        for (int released = 0; released < 40; released++)
        {
            await inner.WaitForStartedAsync(Math.Min(40, released + 1));
            inner.Release(released);
        }
        var results = await Task.WhenAll(calls);

        Assert.True(inner.Peak <= 3, $"peak concurrency {inner.Peak}");
        Assert.All(results, r => Assert.True(r.Success, r.Reason));
    }

    [Fact]
    public async Task PerEndpointLimitBindsEvenWhenTotalWouldAllowMore()
    {
        var inner = new GatedExecutor();
        var exec = Build(inner, b => { b.Total = 50; b.PerEndpoint = 2; });

        var calls = Enumerable.Range(0, 6)
            .Select(i => exec.InvokeAsync(Tool($"t{i}", "shared-endpoint"), NoArgs, Ctx($"t{i}"), CancellationToken.None))
            .ToArray();

        await inner.WaitForStartedAsync(2);
        await Task.Delay(100);
        Assert.Equal(2, inner.Started);

        for (int i = 0; i < 6; i++) { await inner.WaitForStartedAsync(Math.Min(6, i + 1)); inner.Release(i); }
        await Task.WhenAll(calls);
        Assert.True(inner.Peak <= 2);
    }

    [Fact]
    public async Task PerToolLimitBindsEvenWhenEndpointAndTotalWouldAllowMore()
    {
        var inner = new GatedExecutor();
        var exec = Build(inner, b => { b.Total = 50; b.PerEndpoint = 50; b.PerTool = 1; });

        var calls = Enumerable.Range(0, 4)
            .Select(_ => exec.InvokeAsync(Tool("same-tool"), NoArgs, Ctx("same-tool"), CancellationToken.None))
            .ToArray();

        await inner.WaitForStartedAsync(1);
        await Task.Delay(100);
        Assert.Equal(1, inner.Started);

        for (int i = 0; i < 4; i++) { await inner.WaitForStartedAsync(i + 1); inner.Release(i); }
        await Task.WhenAll(calls);
        Assert.Equal(1, inner.Peak);
    }

    // ------------------------------------------------------------------ queue bounds

    [Fact]
    public async Task CallersBeyondTheQueueAreRefusedImmediately()
    {
        var inner = new GatedExecutor();
        var exec = Build(inner, b => { b.Total = 1; b.PerEndpoint = 1; b.PerTool = 1; b.Queue = 1; });

        var running = exec.InvokeAsync(Tool("a", "e1"), NoArgs, Ctx("a"), CancellationToken.None);
        await inner.WaitForStartedAsync(1);

        var queued = exec.InvokeAsync(Tool("b", "e2"), NoArgs, Ctx("b"), CancellationToken.None);
        await Task.Delay(100);
        Assert.Equal(1, exec.WaitingCount);

        var started = DateTime.UtcNow;
        var refused = await exec.InvokeAsync(Tool("c", "e3"), NoArgs, Ctx("c"), CancellationToken.None);

        Assert.False(refused.Success);
        Assert.Equal("capacity-exceeded", refused.Reason);
        Assert.True(DateTime.UtcNow - started < TimeSpan.FromSeconds(1), "refusal must not wait");
        Assert.Equal(1, inner.Started);

        inner.Release(0);
        await inner.WaitForStartedAsync(2);
        inner.Release(1);
        Assert.True((await running).Success);
        Assert.True((await queued).Success);
    }

    [Fact]
    public async Task AZeroLengthQueueRefusesAnyCallerThatWouldHaveToWait()
    {
        var inner = new GatedExecutor();
        var exec = Build(inner, b => { b.Total = 1; b.Queue = 0; });

        var first = exec.InvokeAsync(Tool("a"), NoArgs, Ctx("a"), CancellationToken.None);
        await inner.WaitForStartedAsync(1);

        var second = await exec.InvokeAsync(Tool("b", "other"), NoArgs, Ctx("b"), CancellationToken.None);
        Assert.Equal("capacity-exceeded", second.Reason);

        inner.ReleaseAll();
        await first;
    }

    [Fact]
    public async Task AWaitingCallerGivesUpAfterTheQueueWaitTimeout()
    {
        var inner = new GatedExecutor();
        var exec = Build(inner, b => { b.Total = 1; b.Queue = 5; b.QueueWait = TimeSpan.FromMilliseconds(150); });

        var first = exec.InvokeAsync(Tool("a"), NoArgs, Ctx("a"), CancellationToken.None);
        await inner.WaitForStartedAsync(1);

        var waiter = await exec.InvokeAsync(Tool("b", "other"), NoArgs, Ctx("b"), CancellationToken.None);

        Assert.Equal("capacity-wait-timeout", waiter.Reason);
        Assert.Equal(1, inner.Started);
        Assert.Equal(0, exec.WaitingCount);

        inner.ReleaseAll();
        await first;
    }

    [Fact]
    public async Task CancellingWhileWaitingForASlotAbandonsTheWait()
    {
        var inner = new GatedExecutor();
        var exec = Build(inner, b => { b.Total = 1; b.Queue = 5; });

        var first = exec.InvokeAsync(Tool("a"), NoArgs, Ctx("a"), CancellationToken.None);
        await inner.WaitForStartedAsync(1);

        using var cts = new CancellationTokenSource();
        var waiter = exec.InvokeAsync(Tool("b", "other"), NoArgs, Ctx("b"), cts.Token);
        await Task.Delay(100);
        cts.Cancel();

        var result = await waiter;
        Assert.Equal("jea-cancelled", result.Reason);
        Assert.Equal(1, inner.Started);

        inner.ReleaseAll();
        await first;
    }

    // ------------------------------------------------------------------ timeouts and hung calls

    [Fact]
    public async Task ExecutionTimeoutAnswersTheCallerButKeepsTheSlotUntilTheWorkEnds()
    {
        var inner = new GatedExecutor();
        var exec = Build(inner, b => { b.Total = 1; b.Queue = 0; b.Execution = TimeSpan.FromMilliseconds(150); });

        var timedOut = await exec.InvokeAsync(Tool("hang"), NoArgs, Ctx("hang"), CancellationToken.None);

        Assert.False(timedOut.Success);
        Assert.Equal("jea-timeout", timedOut.Reason);
        Assert.True(inner.Tokens[0].IsCancellationRequested, "cancellation must be requested of the inner call");

        // The inner call is still running: capacity is NOT handed out again, so repeated hangs
        // cannot multiply threads or sessions.
        Assert.Equal(1, exec.RunningCount);
        Assert.Equal(1, exec.AbandonedCount);
        var blocked = await exec.InvokeAsync(Tool("next", "other"), NoArgs, Ctx("next"), CancellationToken.None);
        Assert.Equal("capacity-exceeded", blocked.Reason);
        Assert.Equal(1, inner.Started);

        // Only when the underlying work really returns does capacity come back.
        inner.Release(0);
        await WaitUntil(() => exec.RunningCount == 0 && exec.AbandonedCount == 0);

        inner.Gated = false;
        Assert.True((await exec.InvokeAsync(Tool("after"), NoArgs, Ctx("after"), CancellationToken.None)).Success);
    }

    [Fact]
    public async Task TimeoutIsReportedAsOutcomeUnknownNotAsSuccessfulCancellation()
    {
        var inner = new GatedExecutor();
        var exec = Build(inner, b => b.Execution = TimeSpan.FromMilliseconds(100));

        var r = await exec.InvokeAsync(Tool("hang"), NoArgs, Ctx("hang"), CancellationToken.None);

        Assert.Equal("jea-timeout", r.Reason);          // not "jea-cancelled": the work may still be running
        Assert.DoesNotContain("cancelled", r.PayloadJson);
        inner.ReleaseAll();
    }

    [Fact]
    public async Task CallerCancellationDuringExecutionRequestsCancellationAndReportsIt()
    {
        var inner = new GatedExecutor();
        var exec = Build(inner);
        using var cts = new CancellationTokenSource();

        var call = exec.InvokeAsync(Tool("a"), NoArgs, Ctx("a"), cts.Token);
        await inner.WaitForStartedAsync(1);
        cts.Cancel();

        var r = await call;
        Assert.Equal("jea-cancelled", r.Reason);
        Assert.True(inner.Tokens[0].IsCancellationRequested);
        Assert.Equal(1, exec.RunningCount);              // still occupying its slot until it really returns

        inner.ReleaseAll();
        await WaitUntil(() => exec.RunningCount == 0);
    }

    [Fact]
    public async Task SlotsAreReleasedWhenTheInnerExecutorThrows()
    {
        var inner = new GatedExecutor { Gated = false, Throw = new InvalidOperationException("boom") };
        var exec = Build(inner, b => { b.Total = 1; b.PerEndpoint = 1; b.PerTool = 1; b.Queue = 0; });

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            exec.InvokeAsync(Tool("a"), NoArgs, Ctx("a"), CancellationToken.None));
        await WaitUntil(() => exec.RunningCount == 0);

        inner.Throw = null;
        Assert.True((await exec.InvokeAsync(Tool("a"), NoArgs, Ctx("a"), CancellationToken.None)).Success);
    }

    [Fact]
    public async Task AllResourcesAreBackToZeroAfterAMixedLoad()
    {
        var inner = new GatedExecutor { Gated = false };
        var exec = Build(inner, b => { b.Total = 4; b.PerEndpoint = 2; b.PerTool = 2; b.Queue = 1000; });

        var results = await Task.WhenAll(Enumerable.Range(0, 200).Select(i =>
            exec.InvokeAsync(Tool($"t{i % 7}", $"e{i % 3}"), NoArgs, Ctx($"t{i % 7}", $"S{i}"), CancellationToken.None)));

        Assert.All(results, r => Assert.True(r.Success, r.Reason));
        await WaitUntil(() => exec.RunningCount == 0 && exec.WaitingCount == 0);
        Assert.True(inner.Peak <= 4);
        Assert.Equal(200, inner.Started);
    }

    // ------------------------------------------------------------------ response size

    [Fact]
    public async Task OversizedResponseIsDiscardedNotReturned()
    {
        var inner = new GatedExecutor { Gated = false };
        inner.Result = _ => new JeaInvocationResult(true, 0, "[\"" + new string('x', 200) + "\"]", 1, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow);
        var exec = Build(inner, b => b.MaxResponseBytes = 100);

        var r = await exec.InvokeAsync(Tool("big"), NoArgs, Ctx("big"), CancellationToken.None);

        Assert.False(r.Success);
        Assert.Equal("response-too-large", r.Reason);
        Assert.DoesNotContain("xxxx", r.PayloadJson);
    }

    [Fact]
    public async Task ResponseExactlyAtTheLimitIsAccepted()
    {
        var payload = "[\"" + new string('x', 96) + "\"]";   // 100 bytes
        Assert.Equal(100, System.Text.Encoding.UTF8.GetByteCount(payload));
        var inner = new GatedExecutor { Gated = false };
        inner.Result = _ => new JeaInvocationResult(true, 0, payload, 1, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow);

        var r = await Build(inner, b => b.MaxResponseBytes = 100).InvokeAsync(Tool("t"), NoArgs, Ctx(), CancellationToken.None);
        Assert.True(r.Success);
    }

    [Fact]
    public async Task SizeIsMeasuredInUtf8BytesNotCharacters()
    {
        var payload = "[\"" + new string('€', 40) + "\"]";   // 40 chars but 120+ bytes
        var inner = new GatedExecutor { Gated = false };
        inner.Result = _ => new JeaInvocationResult(true, 0, payload, 1, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow);

        var r = await Build(inner, b => b.MaxResponseBytes = 100).InvokeAsync(Tool("t"), NoArgs, Ctx(), CancellationToken.None);
        Assert.Equal("response-too-large", r.Reason);
    }

    [Fact]
    public async Task AFailedResultPassesThroughUnchanged()
    {
        var inner = new GatedExecutor { Gated = false };
        inner.Result = _ => new JeaInvocationResult(false, 1, "{}", 1, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, "jea-execution-error");
        var r = await Build(inner).InvokeAsync(Tool("t"), NoArgs, Ctx(), CancellationToken.None);
        Assert.Equal("jea-execution-error", r.Reason);
    }

    // ------------------------------------------------------------------ configuration

    [Theory]
    [InlineData(0, 1, 1, 0)]
    [InlineData(1, 0, 1, 0)]
    [InlineData(1, 1, 0, 0)]
    [InlineData(1, 1, 1, -1)]
    public void InvalidLimitsAreRejectedAtConstruction(int total, int endpoint, int tool, int queue)
    {
        var limits = new JeaExecutionLimits
        {
            MaxConcurrentTotal = total, MaxConcurrentPerEndpoint = endpoint, MaxConcurrentPerTool = tool, MaxQueueLength = queue
        };
        Assert.Throws<ArgumentException>(() =>
            new BoundedJeaExecutor(new GatedExecutor(), limits, NullLogger<BoundedJeaExecutor>.Instance));
    }

    [Fact]
    public void NonPositiveTimeoutsAndSizesAreRejected()
    {
        Assert.Throws<ArgumentException>(() => new JeaExecutionLimits { ExecutionTimeout = TimeSpan.Zero }.Validate());
        Assert.Throws<ArgumentException>(() => new JeaExecutionLimits { QueueWaitTimeout = TimeSpan.Zero }.Validate());
        Assert.Throws<ArgumentException>(() => new JeaExecutionLimits { MaxResponseBytes = 0 }.Validate());
        new JeaExecutionLimits().Validate();
    }

    private static async Task WaitUntil(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (!condition() && DateTime.UtcNow < deadline) await Task.Delay(10);
        Assert.True(condition(), "condition not reached in time");
    }
}

public class JeaEndpointClientFailureTests
{
    private static ToolManifest Tool() => new()
    {
        ToolId = "t",
        JeaMapping = new JeaMapping { EndpointName = "McpBroker.DoesNotExist.Test", Cmdlet = "Get-Nothing" }
    };

    [Fact]
    public async Task ACancelledCallReturnsWithoutCreatingAnySession()
    {
        var client = new JeaEndpointClient(NullLogger<JeaEndpointClient>.Instance, new JeaClientOptions(1000, 1000));
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var r = await client.InvokeAsync(Tool(), new Dictionary<string, object>(), CallContext.New("S", "t"), cts.Token);

        Assert.False(r.Success);
        Assert.Equal("jea-cancelled", r.Reason);
    }

    [Fact]
    public async Task SessionSetupFailureIsAFailedResultNeverAnException()
    {
        // No such endpoint exists (and off Windows there is no WSMan client at all), so opening the
        // session must fail; that has to surface as a result, not escape InvokeAsync.
        var client = new JeaEndpointClient(NullLogger<JeaEndpointClient>.Instance, new JeaClientOptions(2000, 2000));

        var r = await client.InvokeAsync(Tool(), new Dictionary<string, object>(), CallContext.New("S", "t"), CancellationToken.None);

        Assert.False(r.Success);
        Assert.Equal(2, r.ExitCode);
        Assert.DoesNotContain("   at ", r.PayloadJson);     // no stack trace in anything returned
        Assert.DoesNotContain("Exception", r.PayloadJson);
    }
}
