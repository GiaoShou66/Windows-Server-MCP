using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using Broker.Core;
using Broker.Registry;
using Microsoft.Extensions.Logging;

namespace Broker.JeaExecution;

/// <summary>
/// Resource limits applied in front of every JEA invocation. Per-caller rate limits are
/// enforced separately (RateLimiter); these limits bound what many authorized callers can
/// do to the host collectively.
/// </summary>
public sealed record JeaExecutionLimits
{
    public int MaxConcurrentTotal { get; init; } = 8;
    public int MaxConcurrentPerEndpoint { get; init; } = 4;
    public int MaxConcurrentPerTool { get; init; } = 2;
    /// <summary>Callers allowed to block waiting for a slot. Beyond this, requests are refused at once.</summary>
    public int MaxQueueLength { get; init; } = 16;
    public TimeSpan QueueWaitTimeout { get; init; } = TimeSpan.FromSeconds(5);
    public TimeSpan ExecutionTimeout { get; init; } = TimeSpan.FromSeconds(60);
    public int MaxResponseBytes { get; init; } = 512 * 1024;

    public void Validate()
    {
        if (MaxConcurrentTotal < 1 || MaxConcurrentPerEndpoint < 1 || MaxConcurrentPerTool < 1)
            throw new ArgumentException("Concurrency limits must be >= 1.");
        if (MaxQueueLength < 0) throw new ArgumentException("MaxQueueLength must be >= 0.");
        if (QueueWaitTimeout <= TimeSpan.Zero || ExecutionTimeout <= TimeSpan.Zero)
            throw new ArgumentException("Timeouts must be positive.");
        if (MaxResponseBytes < 1) throw new ArgumentException("MaxResponseBytes must be >= 1.");
    }
}

/// <summary>
/// Decorator that bounds concurrency (global / per endpoint / per tool), queue length, queue
/// wait, execution time and response size around the real executor.
///
/// Slot lifetime: a slot is held until the inner call has actually returned, even when the
/// caller has already been told "timeout". If a PowerShell call hangs, the caller gets a
/// deterministic answer but capacity stays consumed, so a hung call can never cause
/// unbounded thread or session growth. A timeout means "outcome unknown": cancellation is
/// requested (PowerShell.Stop()), but the broker does not claim the remote work was terminated.
/// </summary>
public sealed class BoundedJeaExecutor : IJeaExecutor
{
    private readonly IJeaExecutor _inner;
    private readonly JeaExecutionLimits _limits;
    private readonly ILogger<BoundedJeaExecutor> _logger;
    private readonly SemaphoreSlim _total;
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _perEndpoint = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _perTool = new(StringComparer.Ordinal);
    private int _waiting;
    private int _running;
    private int _abandoned;

    public BoundedJeaExecutor(IJeaExecutor inner, JeaExecutionLimits limits, ILogger<BoundedJeaExecutor> logger)
    {
        limits.Validate();
        _inner = inner;
        _limits = limits;
        _logger = logger;
        _total = new SemaphoreSlim(limits.MaxConcurrentTotal, limits.MaxConcurrentTotal);
    }

    /// <summary>Inner calls currently executing (including ones whose caller already timed out).</summary>
    public int RunningCount => Volatile.Read(ref _running);
    /// <summary>Callers currently blocked waiting for a slot.</summary>
    public int WaitingCount => Volatile.Read(ref _waiting);
    /// <summary>Calls whose caller was told timeout/cancel but whose inner work has not yet returned.</summary>
    public int AbandonedCount => Volatile.Read(ref _abandoned);

    public async Task<JeaInvocationResult> InvokeAsync(
        ToolManifest tool, IReadOnlyDictionary<string, object> argv, CallContext context, CancellationToken ct)
    {
        var start = DateTimeOffset.UtcNow;

        var toolSem = _perTool.GetOrAdd(tool.ToolId, _ => new SemaphoreSlim(_limits.MaxConcurrentPerTool));
        var endpointSem = _perEndpoint.GetOrAdd(
            tool.JeaMapping.EndpointName, _ => new SemaphoreSlim(_limits.MaxConcurrentPerEndpoint));

        // Fixed acquisition order (tool -> endpoint -> total) rules out lock cycles.
        var held = new List<SemaphoreSlim>(3);
        try
        {
            using var waitCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            waitCts.CancelAfter(_limits.QueueWaitTimeout);
            foreach (var sem in new[] { toolSem, endpointSem, _total })
            {
                if (!await AcquireAsync(sem, waitCts.Token).ConfigureAwait(false))
                {
                    ReleaseHeld(held);
                    return Rejected(start, "capacity-exceeded");
                }
                held.Add(sem);
            }
        }
        catch (OperationCanceledException)
        {
            ReleaseHeld(held);
            return Rejected(start, ct.IsCancellationRequested ? "jea-cancelled" : "capacity-wait-timeout");
        }

        Interlocked.Increment(ref _running);
        // Not disposed here: an abandoned inner call may still hold this token. It is
        // disposed together with the slots, once the inner call has really returned.
        var execCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        Task<JeaInvocationResult> inner;
        try
        {
            inner = _inner.InvokeAsync(tool, argv, context, execCts.Token);
        }
        catch
        {
            Finish(held, execCts);
            throw;
        }

        var finished = inner.ContinueWith(
            _ => Finish(held, execCts), CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);

        using var delayCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var timeoutTask = Task.Delay(_limits.ExecutionTimeout, delayCts.Token);
        var first = await Task.WhenAny(inner, timeoutTask).ConfigureAwait(false);

        if (first == inner)
        {
            delayCts.Cancel();
            return EnforceResponseSize(await inner.ConfigureAwait(false));
        }

        // Timeout, or caller cancelled, while the inner call is still running.
        try { execCts.Cancel(); } catch (ObjectDisposedException) { }
        Interlocked.Increment(ref _abandoned);
        _ = finished.ContinueWith(_ => Interlocked.Decrement(ref _abandoned), TaskScheduler.Default);
        _ = inner.ContinueWith(t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted);

        var reason = ct.IsCancellationRequested ? "jea-cancelled" : "jea-timeout";
        _logger.LogWarning(
            "JEA call for {Tool} ({Corr}) ended with {Reason}; cancellation requested, remote outcome unknown",
            tool.ToolId, context.CorrelationId, reason);
        return Rejected(start, reason);
    }

    /// <summary>Takes a slot immediately if free; otherwise queues, unless the queue is full.</summary>
    private async Task<bool> AcquireAsync(SemaphoreSlim sem, CancellationToken token)
    {
        if (sem.Wait(0)) return true;

        if (Interlocked.Increment(ref _waiting) > _limits.MaxQueueLength)
        {
            Interlocked.Decrement(ref _waiting);
            return false;
        }

        try
        {
            await sem.WaitAsync(token).ConfigureAwait(false);
            return true;
        }
        finally
        {
            Interlocked.Decrement(ref _waiting);
        }
    }

    private static void ReleaseHeld(List<SemaphoreSlim> held)
    {
        for (int i = held.Count - 1; i >= 0; i--) held[i].Release();
        held.Clear();
    }

    private void Finish(List<SemaphoreSlim> held, CancellationTokenSource execCts)
    {
        Interlocked.Decrement(ref _running);
        try { execCts.Dispose(); } catch (ObjectDisposedException) { }
        ReleaseHeld(held);
    }

    private JeaInvocationResult EnforceResponseSize(JeaInvocationResult result)
    {
        if (!result.Success) return result;
        if (Encoding.UTF8.GetByteCount(result.PayloadJson) <= _limits.MaxResponseBytes) return result;

        _logger.LogWarning("JEA response exceeded {Max} bytes and was discarded", _limits.MaxResponseBytes);
        return result with
        {
            Success = false,
            PayloadJson = JsonSerializer.Serialize(new { error = "response-too-large" }),
            Reason = "response-too-large"
        };
    }

    private static JeaInvocationResult Rejected(DateTimeOffset start, string reason)
    {
        var ended = DateTimeOffset.UtcNow;
        return new JeaInvocationResult(false, 5,
            JsonSerializer.Serialize(new { error = reason }), (long)(ended - start).TotalMilliseconds,
            start, ended, reason);
    }
}
