using System.Text.Json;
using System.Threading.Channels;
using Broker.Core;
using Broker.Transport;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Broker.Tests;

/// <summary>
/// Minimal in-memory duplex stream pair, used in place of a real named pipe so
/// NamedPipeServer.ServeAsync can be exercised in-process without OS pipe setup.
/// </summary>
internal sealed class ChannelStream : Stream
{
    private readonly ChannelReader<byte[]> _reader;
    private readonly ChannelWriter<byte[]> _writer;
    private byte[] _pending = Array.Empty<byte>();
    private int _pendingOffset;

    private ChannelStream(ChannelReader<byte[]> reader, ChannelWriter<byte[]> writer)
    {
        _reader = reader;
        _writer = writer;
    }

    public static (Stream a, Stream b) CreatePair()
    {
        var ab = Channel.CreateUnbounded<byte[]>();
        var ba = Channel.CreateUnbounded<byte[]>();
        var a = new ChannelStream(ba.Reader, ab.Writer);
        var b = new ChannelStream(ab.Reader, ba.Writer);
        return (a, b);
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
    {
        if (_pendingOffset >= _pending.Length)
        {
            if (!await _reader.WaitToReadAsync(ct)) return 0;
            if (!_reader.TryRead(out var chunk)) return 0;
            _pending = chunk;
            _pendingOffset = 0;
        }

        int n = Math.Min(buffer.Length, _pending.Length - _pendingOffset);
        _pending.AsSpan(_pendingOffset, n).CopyTo(buffer.Span);
        _pendingOffset += n;
        return n;
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
        => await _writer.WriteAsync(buffer.ToArray(), ct);

    public override int Read(byte[] buffer, int offset, int count)
        => ReadAsync(buffer.AsMemory(offset, count)).GetAwaiter().GetResult();

    public override void Write(byte[] buffer, int offset, int count)
        => WriteAsync(buffer.AsMemory(offset, count)).GetAwaiter().GetResult();

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override bool CanRead => true;
    public override bool CanWrite => true;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
}

/// <summary>Dispatcher stub: "echo" tools return immediately, "gated" tools call elicitation first.</summary>
internal sealed class StubDispatcher : IToolCallDispatcher
{
    /// <summary>Captures the reply the pipeline actually received, for tests that need to
    /// inspect DecidedBySid independently of whatever ConsentEngine would do with it.</summary>
    public ElicitationReply? LastReply { get; private set; }

    public async Task<ToolCallResult> DispatchAsync(
        ToolCallRequest request, CallContext context, ElicitationChannel elicitation, CancellationToken ct)
    {
        if (request.ToolId == "echo")
            return ToolCallResult.Ok("{\"ok\":true}");

        if (request.ToolId == "gated")
        {
            var paramHash = "fixed-hash";
            var ectx = new ElicitationContext(context.CorrelationId, request.ToolId, context.CallerSid, paramHash);
            var reply = await elicitation.RequestAsync(ectx, ct);
            LastReply = reply;

            return reply.Approved && reply.ParamHash == paramHash
                ? ToolCallResult.Ok("{\"approved\":true}")
                : ToolCallResult.Rejected("elicitation-denied");
        }

        return ToolCallResult.Rejected("unknown-tool");
    }
}

public class TransportIntegrationTests
{
    private static NamedPipeServer BuildServer(out ElicitationRouter router, bool distinctApprover = false)
        => BuildServer(out router, out _, distinctApprover);

    private static NamedPipeServer BuildServer(out ElicitationRouter router, out StubDispatcher dispatcher, bool distinctApprover = false)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Pipe:Name"] = "test",
            ["Pipe:FrameTimeoutSeconds"] = "5",
            ["Elicitation:TtlSeconds"] = "5",
            ["Elicitation:RequireDistinctApprover"] = distinctApprover ? "true" : "false"
        }).Build();

        var securityFactory = new PipeSecurityFactory(config, NullLogger<PipeSecurityFactory>.Instance);
        router = new ElicitationRouter(NullLogger<ElicitationRouter>.Instance);
        dispatcher = new StubDispatcher();
        return new NamedPipeServer(securityFactory, dispatcher, router, config,
            NullLogger<NamedPipeServer>.Instance);
    }

    private static async Task WriteJsonAsync(Stream s, object obj, CancellationToken ct)
        => await McpFraming.WriteFrameAsync(s, JsonSerializer.Serialize(obj), ct);

    private static async Task<JsonElement> ReadJsonAsync(Stream s, CancellationToken ct)
    {
        var frame = await McpFraming.ReadFrameAsync(s, TimeSpan.FromSeconds(5), ct);
        Assert.NotNull(frame);
        return JsonDocument.Parse(frame!).RootElement.Clone();
    }

    [Fact]
    public async Task EchoToolRoundTrips()
    {
        var server = BuildServer(out _);
        var (serverSide, clientSide) = ChannelStream.CreatePair();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var serveTask = server.ServeAsync(serverSide, () => true, "CALLER-SID", cts.Token);

        await WriteJsonAsync(clientSide, new { type = "tools/call", toolId = "echo", parameters = new { } }, cts.Token);
        var result = await ReadJsonAsync(clientSide, cts.Token);

        Assert.Equal("tools/result", result.GetProperty("type").GetString());
        Assert.True(result.GetProperty("success").GetBoolean());

        cts.Cancel();
        await Task.WhenAny(serveTask, Task.Delay(1000));
    }

    /// <summary>
    /// Regression test for the elicitation deadlock (fix 1): the reader must be able to
    /// read the elicitation/reply frame WHILE the dispatch task is still awaiting it. In the
    /// original design the read loop awaited DispatchAsync directly, so this would hang until
    /// the outer CancellationTokenSource timeout fired. The WaitAsync bound here fails fast
    /// instead of hanging the whole test run if the deadlock is ever reintroduced.
    /// </summary>
    [Fact]
    public async Task ElicitationApprovedCompletesCallWithoutDeadlock()
    {
        var server = BuildServer(out _);
        var (serverSide, clientSide) = ChannelStream.CreatePair();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var serveTask = server.ServeAsync(serverSide, () => true, "CALLER-SID", cts.Token);

        var exchange = Task.Run(async () =>
        {
            await WriteJsonAsync(clientSide, new { type = "tools/call", toolId = "gated", parameters = new { } }, cts.Token);

            var request = await ReadJsonAsync(clientSide, cts.Token);
            Assert.Equal("elicitation/request", request.GetProperty("type").GetString());
            var correlationId = request.GetProperty("correlationId").GetString();
            var paramHash = request.GetProperty("paramHash").GetString();
            Assert.Equal("fixed-hash", paramHash);

            await WriteJsonAsync(clientSide, new
            {
                type = "elicitation/reply",
                correlationId,
                paramHash,
                approved = true
            }, cts.Token);

            return await ReadJsonAsync(clientSide, cts.Token);
        });

        var result = await exchange.WaitAsync(TimeSpan.FromSeconds(8));

        Assert.Equal("tools/result", result.GetProperty("type").GetString());
        Assert.True(result.GetProperty("success").GetBoolean());

        cts.Cancel();
        await Task.WhenAny(serveTask, Task.Delay(1000));
    }

    /// <summary>
    /// Regression test for a P0 authorization bypass: ParseElicitationReply used to read an
    /// optional "decidedBySid" field from the reply JSON and trust it as the approver identity
    /// when present, falling back to the connection's real callerSid only when absent. Since
    /// the caller controls its own reply message, this let a caller self-approve any
    /// write/destructive call by simply claiming a forged, different-looking approver SID —
    /// completely defeating ConsentEngine's self-approval-forbidden check, which has no way to
    /// know the "decidedBySid" it receives was never authenticated. The fix removes the
    /// client-controllable field entirely; this test proves a forged value in the wire
    /// protocol is silently discarded and the real connection identity is used instead.
    /// </summary>
    [Fact]
    public async Task ForgedDecidedBySidInReplyIsIgnoredAndRealCallerSidIsUsed()
    {
        var server = BuildServer(out _, out var dispatcher);
        var (serverSide, clientSide) = ChannelStream.CreatePair();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        const string realCallerSid = "REAL-CALLER-SID";
        const string forgedApproverSid = "S-1-5-21-FORGED-DISTINCT-APPROVER";

        var serveTask = server.ServeAsync(serverSide, () => true, realCallerSid, cts.Token);

        var exchange = Task.Run(async () =>
        {
            await WriteJsonAsync(clientSide, new { type = "tools/call", toolId = "gated", parameters = new { } }, cts.Token);

            var request = await ReadJsonAsync(clientSide, cts.Token);
            var correlationId = request.GetProperty("correlationId").GetString();
            var paramHash = request.GetProperty("paramHash").GetString();

            // The attack: the SAME connection that made the call also answers the elicitation,
            // claiming (via a field it fully controls) to be a distinct approver identity.
            await WriteJsonAsync(clientSide, new
            {
                type = "elicitation/reply",
                correlationId,
                paramHash,
                approved = true,
                decidedBySid = forgedApproverSid
            }, cts.Token);

            return await ReadJsonAsync(clientSide, cts.Token);
        });

        await exchange.WaitAsync(TimeSpan.FromSeconds(8));

        Assert.NotNull(dispatcher.LastReply);
        Assert.Equal(realCallerSid, dispatcher.LastReply!.DecidedBySid);
        Assert.NotEqual(forgedApproverSid, dispatcher.LastReply.DecidedBySid);

        cts.Cancel();
        await Task.WhenAny(serveTask, Task.Delay(1000));
    }

    [Fact]
    public async Task ElicitationDeniedRejectsCall()
    {
        var server = BuildServer(out _);
        var (serverSide, clientSide) = ChannelStream.CreatePair();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var serveTask = server.ServeAsync(serverSide, () => true, "CALLER-SID", cts.Token);

        await WriteJsonAsync(clientSide, new { type = "tools/call", toolId = "gated", parameters = new { } }, cts.Token);
        var request = await ReadJsonAsync(clientSide, cts.Token);
        var correlationId = request.GetProperty("correlationId").GetString();

        await WriteJsonAsync(clientSide, new
        {
            type = "elicitation/reply",
            correlationId,
            paramHash = "fixed-hash",
            approved = false
        }, cts.Token);

        var result = await ReadJsonAsync(clientSide, cts.Token);
        Assert.False(result.GetProperty("success").GetBoolean());

        cts.Cancel();
        await Task.WhenAny(serveTask, Task.Delay(1000));
    }
}

public class ElicitationRouterTests
{
    [Fact]
    public async Task ApproverCanResolveCallerRequest()
    {
        var router = new ElicitationRouter(NullLogger<ElicitationRouter>.Instance);
        var received = new TaskCompletionSource<PendingElicitation>();

        using var reg = router.RegisterApprover(pe => { received.TrySetResult(pe); return Task.CompletedTask; },
            out var backlog);
        Assert.Empty(backlog);

        var ctx = new ElicitationContext("corr-1", "write-tool", "CALLER", "hash-1");
        var requestTask = router.RequestAsync(ctx, TimeSpan.FromSeconds(5), CancellationToken.None);

        var notified = await received.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Equal("corr-1", notified.CorrelationId);

        var resolved = router.TryResolve("corr-1", new ElicitationReply("corr-1", "hash-1", true, "APPROVER-SID", "write-tool"));
        Assert.True(resolved);

        var reply = await requestTask.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.True(reply.Approved);
        Assert.Equal("APPROVER-SID", reply.DecidedBySid);
    }

    [Fact]
    public async Task RequestTimesOutWithNoApprover()
    {
        var router = new ElicitationRouter(NullLogger<ElicitationRouter>.Instance);
        var ctx = new ElicitationContext("corr-2", "write-tool", "CALLER", "hash-2");

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await router.RequestAsync(ctx, TimeSpan.FromMilliseconds(200), CancellationToken.None));
    }

    [Fact]
    public async Task ExpiredApprovalAndMismatchedToolAreRejected()
    {
        var router = new ElicitationRouter(NullLogger<ElicitationRouter>.Instance);
        var ctx = new ElicitationContext("corr-3", "write-tool", "CALLER", "hash-3");
        var requestTask = router.RequestAsync(ctx, TimeSpan.FromMilliseconds(50), CancellationToken.None);

        await Task.Delay(100);

        Assert.False(router.TryResolve("corr-3",
            new ElicitationReply("corr-3", "hash-3", true, "APPROVER-SID", "other-tool")));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await requestTask);
    }
}
