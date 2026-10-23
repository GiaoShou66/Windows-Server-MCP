using Broker.Core;
using Broker.Policy;
using Xunit;

namespace Broker.Tests;

public class TaintTrackerBehaviourTests
{
    [Fact]
    public void TaintLastsForTheWindowAndThenExpires()
    {
        var clock = new ManualTimeProvider();
        var t = new TaintTracker(300, clock);

        t.MarkTainted("A");
        clock.Advance(TimeSpan.FromSeconds(299));
        Assert.True(t.IsTainted("A"));

        clock.Advance(TimeSpan.FromSeconds(2));
        Assert.False(t.IsTainted("A"));
    }

    [Fact]
    public void MarkingAgainExtendsTheWindowFromNow()
    {
        var clock = new ManualTimeProvider();
        var t = new TaintTracker(300, clock);

        t.MarkTainted("A");
        clock.Advance(TimeSpan.FromSeconds(200));
        t.MarkTainted("A");
        clock.Advance(TimeSpan.FromSeconds(200));

        Assert.True(t.IsTainted("A"));   // 400s after first mark, 200s after the second
        clock.Advance(TimeSpan.FromSeconds(101));
        Assert.False(t.IsTainted("A"));
    }

    [Fact]
    public void CallersAreTaintedIndependently()
    {
        var t = new TaintTracker(300, new ManualTimeProvider());
        t.MarkTainted("A");
        Assert.True(t.IsTainted("A"));
        Assert.False(t.IsTainted("B"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void ABlankCallerIdentityIsAlwaysTreatedAsTainted(string sid)
    {
        var t = new TaintTracker(300, new ManualTimeProvider());
        Assert.True(t.IsTainted(sid));
    }

    [Fact]
    public void ExpiredEntriesAreRemovedSoStateDoesNotGrowForever()
    {
        var clock = new ManualTimeProvider();
        var t = new TaintTracker(60, clock);

        for (int i = 0; i < 100; i++) t.MarkTainted($"SID-{i}");
        Assert.Equal(100, t.TrackedCallerCount);

        clock.Advance(TimeSpan.FromSeconds(120));
        t.MarkTainted("LATE");

        Assert.Equal(1, t.TrackedCallerCount);
    }

    [Fact]
    public async Task ConcurrentMarkAndCheckIsConsistent()
    {
        var t = new TaintTracker(300, new ManualTimeProvider());
        await Task.WhenAll(Enumerable.Range(0, 2000).Select(i => Task.Run(() =>
        {
            var sid = $"SID-{i % 50}";
            t.MarkTainted(sid);
            Assert.True(t.IsTainted(sid));
        })));

        for (int i = 0; i < 50; i++) Assert.True(t.IsTainted($"SID-{i}"));
        Assert.Equal(50, t.TrackedCallerCount);
    }
}

public class RateLimiterBehaviourTests
{
    [Fact]
    public void WindowSlidesSoCallersRecover()
    {
        var clock = new ManualTimeProvider();
        var rl = new RateLimiter(callsPerMinute: 2, destructivePerHour: 10, globalCallsPerMinute: 0, clock);

        Assert.True(rl.Check("A", RiskTier.Read).Allowed);
        Assert.True(rl.Check("A", RiskTier.Read).Allowed);
        Assert.False(rl.Check("A", RiskTier.Read).Allowed);

        clock.Advance(TimeSpan.FromSeconds(61));
        Assert.True(rl.Check("A", RiskTier.Read).Allowed);
    }

    [Fact]
    public void GlobalLimitBindsAcrossDifferentCallers()
    {
        var rl = new RateLimiter(callsPerMinute: 100, destructivePerHour: 10, globalCallsPerMinute: 5, new ManualTimeProvider());

        for (int i = 0; i < 5; i++)
            Assert.True(rl.Check($"CALLER-{i}", RiskTier.Read).Allowed, $"caller {i}");

        var d = rl.Check("CALLER-NEW", RiskTier.Read);
        Assert.False(d.Allowed);
        Assert.Equal("global-rate-limit-exceeded", d.Reason);
    }

    [Fact]
    public void PerCallerLimitStillAppliesBelowTheGlobalLimit()
    {
        var rl = new RateLimiter(callsPerMinute: 2, destructivePerHour: 10, globalCallsPerMinute: 100, new ManualTimeProvider());
        rl.Check("A", RiskTier.Read); rl.Check("A", RiskTier.Read);

        var d = rl.Check("A", RiskTier.Read);
        Assert.False(d.Allowed);
        Assert.Equal("rate-limit-exceeded", d.Reason);
        Assert.True(rl.Check("B", RiskTier.Read).Allowed);
    }

    [Fact]
    public void ZeroDisablesOnlyTheGlobalLimit()
    {
        var rl = new RateLimiter(callsPerMinute: 1000, destructivePerHour: 10, globalCallsPerMinute: 0, new ManualTimeProvider());
        for (int i = 0; i < 500; i++) Assert.True(rl.Check($"C-{i % 20}", RiskTier.Read).Allowed);
    }

    [Fact]
    public void ADeniedCallDoesNotConsumeAnyBudget()
    {
        var rl = new RateLimiter(callsPerMinute: 3, destructivePerHour: 1, globalCallsPerMinute: 100, new ManualTimeProvider());

        Assert.True(rl.Check("A", RiskTier.Destructive).Allowed);
        // Denied by the destructive budget: must not use up the general per-minute budget.
        Assert.False(rl.Check("A", RiskTier.Destructive).Allowed);
        Assert.False(rl.Check("A", RiskTier.Destructive).Allowed);

        Assert.True(rl.Check("A", RiskTier.Read).Allowed);
        Assert.True(rl.Check("A", RiskTier.Read).Allowed);
        Assert.False(rl.Check("A", RiskTier.Read).Allowed);   // 1 destructive + 2 reads = 3 consumed
    }

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    public void ABlankCallerIdentityIsDenied(string sid)
    {
        var d = new RateLimiter().Check(sid, RiskTier.Read);
        Assert.False(d.Allowed);
        Assert.Equal("caller-identity-missing", d.Reason);
    }

    [Fact]
    public void IdleCallerStateIsPruned()
    {
        var clock = new ManualTimeProvider();
        var rl = new RateLimiter(60, 10, 0, clock);

        for (int i = 0; i < 100; i++) rl.Check($"SID-{i}", RiskTier.Read);
        Assert.Equal(100, rl.TrackedCallerCount);

        clock.Advance(TimeSpan.FromMinutes(5));
        rl.Check("SID-0", RiskTier.Read);

        Assert.Equal(1, rl.TrackedCallerCount);
    }

    [Fact]
    public async Task ConcurrentCallsNeverExceedEitherBound()
    {
        var rl = new RateLimiter(callsPerMinute: 5, destructivePerHour: 10, globalCallsPerMinute: 60, new ManualTimeProvider());
        var allowedPerCaller = new System.Collections.Concurrent.ConcurrentDictionary<string, int>();
        var allowedTotal = 0;

        await Task.WhenAll(Enumerable.Range(0, 400).Select(i => Task.Run(() =>
        {
            var sid = $"SID-{i % 20}";
            if (rl.Check(sid, RiskTier.Read).Allowed)
            {
                Interlocked.Increment(ref allowedTotal);
                allowedPerCaller.AddOrUpdate(sid, 1, (_, n) => n + 1);
            }
        })));

        Assert.All(allowedPerCaller.Values, n => Assert.True(n <= 5));
        Assert.True(allowedTotal <= 60, $"allowed {allowedTotal}");
        Assert.Equal(60, allowedTotal);   // 20 callers x 5 = 100 > 60, so the global bound is what binds
    }
}
