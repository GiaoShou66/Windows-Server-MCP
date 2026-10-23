using System.Text;
using System.Text.Json;
using Broker.Core;
using Broker.Transport;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Broker.Tests;

internal sealed class RecordingDispatcher : IToolCallDispatcher
{
    private readonly Func<ToolCallRequest, CallContext, ElicitationChannel, CancellationToken, Task<ToolCallResult>>? _fn;
    public RecordingDispatcher(Func<ToolCallRequest, CallContext, ElicitationChannel, CancellationToken, Task<ToolCallResult>>? fn = null) => _fn = fn;

    public List<ToolCallRequest> Requests { get; } = new();
    public List<ElicitationReply> Replies { get; } = new();
    public int Calls => Requests.Count;

    public async Task<ToolCallResult> DispatchAsync(ToolCallRequest request, CallContext context, ElicitationChannel elicitation, CancellationToken ct)
    {
        lock (Requests) Requests.Add(request);
        if (_fn is not null) return await _fn(request, context, elicitation, ct);

        if (request.ToolId == "gated")
        {
            var reply = await elicitation.RequestAsync(
                new ElicitationContext(context.CorrelationId, request.ToolId, context.CallerSid, "h"), ct);
            lock (Replies) Replies.Add(reply);
            return reply.Approved ? ToolCallResult.Ok("{\"approved\":true}") : ToolCallResult.Rejected("elicitation-denied");
        }
        return ToolCallResult.Ok("{\"ok\":true}");
    }
}

public class TransportSecurityTests
{
    private static NamedPipeServer Server(RecordingDispatcher dispatcher, Dictionary<string, string?>? extra = null)
    {
        var cfg = new Dictionary<string, string?>
        {
            ["Pipe:FrameTimeoutSeconds"] = "5",
            ["Elicitation:TtlSeconds"] = "2",
            ["Elicitation:RequireDistinctApprover"] = "false"
        };
        if (extra is not null) foreach (var kv in extra) cfg[kv.Key] = kv.Value;
        var config = new ConfigurationBuilder().AddInMemoryCollection(cfg).Build();
        return new NamedPipeServer(new PipeSecurityFactory(config, NullLogger<PipeSecurityFactory>.Instance),
            dispatcher, new ElicitationRouter(NullLogger<ElicitationRouter>.Instance), config, NullLogger<NamedPipeServer>.Instance);
    }

    private static Task Send(Stream s, string rawJson, CancellationToken ct) => McpFraming.WriteFrameAsync(s, rawJson, ct);
    private static Task Send(Stream s, object o, CancellationToken ct) => McpFraming.WriteFrameAsync(s, JsonSerializer.Serialize(o), ct);

    private static async Task<JsonElement> Read(Stream s, CancellationToken ct)
    {
        var frame = await McpFraming.ReadFrameAsync(s, TimeSpan.FromSeconds(5), ct);
        Assert.NotNull(frame);
        return JsonDocument.Parse(frame!).RootElement.Clone();
    }

    private static string Reason(JsonElement r) => r.GetProperty("rejectReason").GetString()!;

    private static CancellationTokenSource Timeout() => new(TimeSpan.FromSeconds(15));

    // ----------------------------------------------------------------------------- identity

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task ConnectionWithoutAnIdentityIsRefusedBeforeAnythingIsDispatched(string sid)
    {
        var dispatcher = new RecordingDispatcher();
        var server = Server(dispatcher);
        var (serverSide, client) = ChannelStream.CreatePair();
        using var cts = Timeout();

        var serve = server.ServeAsync(serverSide, () => true, sid, cts.Token);
        await Send(client, new { type = "tools/call", toolId = "echo", parameters = new { } }, cts.Token);

        await serve.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(0, dispatcher.Calls);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public void RequireCallerSidRefusesAMissingImpersonatedIdentity(string? sid) =>
        Assert.Throws<InvalidOperationException>(() => NamedPipeServer.RequireCallerSid(sid));

    [Fact]
    public void RequireCallerSidPassesARealIdentityThrough() =>
        Assert.Equal("S-1-5-21-1-2-3-1001", NamedPipeServer.RequireCallerSid("S-1-5-21-1-2-3-1001"));

    // ----------------------------------------------------------------------------- malformed messages

    [Theory]
    [InlineData("{ not json")]
    [InlineData("[1,2,3]")]
    [InlineData("\"just a string\"")]
    [InlineData("42")]
    [InlineData("{\"type\":\"tools/call\"}")]                                              // no toolId
    [InlineData("{\"type\":\"tools/call\",\"toolId\":7}")]                                 // toolId not a string
    [InlineData("{\"type\":\"tools/call\",\"toolId\":\"\"}")]                              // empty toolId
    [InlineData("{\"type\":\"ping\",\"toolId\":\"echo\"}")]                                // unknown message type
    [InlineData("{\"type\":7,\"toolId\":\"echo\"}")]                                       // type not a string
    [InlineData("{\"toolId\":\"echo\",\"parameters\":[\"x\"]}")]                           // parameters not an object
    [InlineData("{\"toolId\":\"echo\",\"parameters\":{\"a\":{\"b\":1}}}")]                 // nested object value
    [InlineData("{\"toolId\":\"echo\",\"parameters\":{\"a\":[1]}}")]                       // array value
    [InlineData("{\"toolId\":\"echo\",\"parameters\":{\"a\":null}}")]                      // null value
    [InlineData("{\"toolId\":\"echo\",\"parameters\":{\"a\":\"1\",\"a\":\"2\"}}")]         // duplicate key
    public async Task MalformedRequestsAreRejectedWithoutDispatchAndTheConnectionSurvives(string raw)
    {
        var dispatcher = new RecordingDispatcher();
        var server = Server(dispatcher);
        var (serverSide, client) = ChannelStream.CreatePair();
        using var cts = Timeout();
        var serve = server.ServeAsync(serverSide, () => true, "CALLER", cts.Token);

        await Send(client, raw, cts.Token);
        var rejection = await Read(client, cts.Token);

        Assert.False(rejection.GetProperty("success").GetBoolean());
        Assert.Equal("malformed-request", Reason(rejection));
        Assert.Equal(0, dispatcher.Calls);

        // The connection is still usable for a well-formed call.
        await Send(client, new { type = "tools/call", toolId = "echo", parameters = new { } }, cts.Token);
        var ok = await Read(client, cts.Token);
        Assert.True(ok.GetProperty("success").GetBoolean());

        cts.Cancel();
        await Task.WhenAny(serve, Task.Delay(1000));
    }

    [Theory]
    [InlineData("Echo")]                       // upper case
    [InlineData("a\nb")]                       // newline: would forge a log line
    [InlineData("has space")]
    [InlineData("-leading")]
    [InlineData("trailing-")]
    [InlineData("double--dash")]
    [InlineData("under_score")]
    [InlineData("a\u202Eb")]
    public async Task AToolIdThatIsNotAPlainIdentifierIsMalformed(string toolId)
    {
        var dispatcher = new RecordingDispatcher();
        var server = Server(dispatcher);
        var (serverSide, client) = ChannelStream.CreatePair();
        using var cts = Timeout();
        var serve = server.ServeAsync(serverSide, () => true, "CALLER", cts.Token);

        await Send(client, new { type = "tools/call", toolId, parameters = new { } }, cts.Token);

        Assert.Equal("malformed-request", Reason(await Read(client, cts.Token)));
        Assert.Equal(0, dispatcher.Calls);

        cts.Cancel();
        await Task.WhenAny(serve, Task.Delay(1000));
    }

    [Fact]
    public async Task AnOverlongToolIdIsMalformedAndNeverReachesTheLogs()
    {
        var dispatcher = new RecordingDispatcher();
        var server = Server(dispatcher);
        var (serverSide, client) = ChannelStream.CreatePair();
        using var cts = Timeout();
        var serve = server.ServeAsync(serverSide, () => true, "CALLER", cts.Token);

        await Send(client, new { type = "tools/call", toolId = new string('a', 5000), parameters = new { } }, cts.Token);

        Assert.Equal("malformed-request", Reason(await Read(client, cts.Token)));
        Assert.Equal(0, dispatcher.Calls);

        cts.Cancel();
        await Task.WhenAny(serve, Task.Delay(1000));
    }

    [Theory]
    [InlineData("echo")]
    [InlineData("list-windows-services")]
    [InlineData("set-ad-group-membership")]
    [InlineData("a1-b2-c3")]
    public async Task ARealToolIdIsAccepted(string toolId)
    {
        var dispatcher = new RecordingDispatcher();
        var server = Server(dispatcher);
        var (serverSide, client) = ChannelStream.CreatePair();
        using var cts = Timeout();
        var serve = server.ServeAsync(serverSide, () => true, "CALLER", cts.Token);

        await Send(client, new { type = "tools/call", toolId, parameters = new { } }, cts.Token);

        Assert.True((await Read(client, cts.Token)).GetProperty("success").GetBoolean());
        Assert.Equal(toolId, dispatcher.Requests.Single().ToolId);

        cts.Cancel();
        await Task.WhenAny(serve, Task.Delay(1000));
    }

    [Fact]
    public async Task ARepeatedlyMalformedClientIsDisconnected()
    {
        var dispatcher = new RecordingDispatcher();
        var server = Server(dispatcher, new() { ["Pipe:MaxMalformedRequests"] = "3" });
        var (serverSide, client) = ChannelStream.CreatePair();
        using var cts = Timeout();
        var serve = server.ServeAsync(serverSide, () => true, "CALLER", cts.Token);

        for (int i = 0; i < 3; i++)
        {
            await Send(client, "{ garbage", cts.Token);
            Assert.Equal("malformed-request", Reason(await Read(client, cts.Token)));
        }

        await serve.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(0, dispatcher.Calls);
    }

    [Fact]
    public async Task JsonBooleansAndNumbersReachTheDispatcherInTheirCanonicalWireForm()
    {
        var dispatcher = new RecordingDispatcher();
        var server = Server(dispatcher);
        var (serverSide, client) = ChannelStream.CreatePair();
        using var cts = Timeout();
        var serve = server.ServeAsync(serverSide, () => true, "CALLER", cts.Token);

        await Send(client, "{\"toolId\":\"echo\",\"parameters\":{\"Enabled\":true,\"Off\":false,\"DaysBack\":7,\"Ratio\":1.5,\"Exp\":1e1,\"Name\":\"x\"}}", cts.Token);
        await Read(client, cts.Token);

        var p = dispatcher.Requests.Single().Parameters;
        Assert.Equal("true", p["Enabled"]);       // not "True": the validator is strict about case
        Assert.Equal("false", p["Off"]);
        Assert.Equal("7", p["DaysBack"]);
        Assert.Equal("1.5", p["Ratio"]);          // raw text preserved so an int parameter rejects it
        Assert.Equal("1e1", p["Exp"]);
        Assert.Equal("x", p["Name"]);

        cts.Cancel();
        await Task.WhenAny(serve, Task.Delay(1000));
    }

    // ----------------------------------------------------------------------------- elicitation replies

    [Fact]
    public async Task NonBooleanApprovedIsNeverTreatedAsApproval()
    {
        var dispatcher = new RecordingDispatcher();
        var server = Server(dispatcher);
        var (serverSide, client) = ChannelStream.CreatePair();
        using var cts = Timeout();
        var serve = server.ServeAsync(serverSide, () => true, "CALLER", cts.Token);

        await Send(client, new { type = "tools/call", toolId = "gated", parameters = new { } }, cts.Token);
        var request = await Read(client, cts.Token);

        await Send(client, $"{{\"type\":\"elicitation/reply\",\"correlationId\":\"{request.GetProperty("correlationId").GetString()}\",\"paramHash\":\"h\",\"approved\":\"true\",\"toolId\":\"gated\"}}", cts.Token);
        var result = await Read(client, cts.Token);

        Assert.False(result.GetProperty("success").GetBoolean());
        Assert.False(dispatcher.Replies.Single().Approved);

        cts.Cancel();
        await Task.WhenAny(serve, Task.Delay(1000));
    }

    [Fact]
    public async Task ReplyForAnUnknownCorrelationIsIgnoredAndHarmless()
    {
        var dispatcher = new RecordingDispatcher();
        var server = Server(dispatcher);
        var (serverSide, client) = ChannelStream.CreatePair();
        using var cts = Timeout();
        var serve = server.ServeAsync(serverSide, () => true, "CALLER", cts.Token);

        await Send(client, new { type = "elicitation/reply", correlationId = "does-not-exist", paramHash = "h", approved = true, toolId = "gated" }, cts.Token);
        await Send(client, new { type = "tools/call", toolId = "echo", parameters = new { } }, cts.Token);

        Assert.True((await Read(client, cts.Token)).GetProperty("success").GetBoolean());
        Assert.Equal(1, dispatcher.Calls);

        cts.Cancel();
        await Task.WhenAny(serve, Task.Delay(1000));
    }

    [Fact]
    public async Task OneConnectionCannotAnswerAnotherConnectionsElicitation()
    {
        var dispatcherA = new RecordingDispatcher();
        var serverA = Server(dispatcherA);
        var (serverSideA, clientA) = ChannelStream.CreatePair();
        var serverB = Server(new RecordingDispatcher());
        var (serverSideB, clientB) = ChannelStream.CreatePair();
        using var cts = Timeout();

        var serveA = serverA.ServeAsync(serverSideA, () => true, "ALICE", cts.Token);
        var serveB = serverB.ServeAsync(serverSideB, () => true, "MALLORY", cts.Token);

        await Send(clientA, new { type = "tools/call", toolId = "gated", parameters = new { } }, cts.Token);
        var request = await Read(clientA, cts.Token);

        // Mallory replays Alice's correlation id on her own connection.
        await Send(clientB, new { type = "elicitation/reply", correlationId = request.GetProperty("correlationId").GetString(), paramHash = "h", approved = true, toolId = "gated" }, cts.Token);

        // Alice's call is not approved; it times out (TTL 2 s).
        var result = await Read(clientA, cts.Token);
        Assert.False(result.GetProperty("success").GetBoolean());
        Assert.Empty(dispatcherA.Replies);

        cts.Cancel();
        await Task.WhenAny(Task.WhenAll(serveA, serveB), Task.Delay(1000));
    }

    // ----------------------------------------------------------------------------- resource bounds

    [Fact]
    public async Task InFlightRequestsPerConnectionAreBounded()
    {
        var release = new TaskCompletionSource();
        var dispatcher = new RecordingDispatcher(async (_, _, _, ct) =>
        {
            await release.Task.WaitAsync(ct);
            return ToolCallResult.Ok("{}");
        });
        var server = Server(dispatcher, new() { ["Pipe:MaxInFlightPerConnection"] = "2" });
        var (serverSide, client) = ChannelStream.CreatePair();
        using var cts = Timeout();
        var serve = server.ServeAsync(serverSide, () => true, "CALLER", cts.Token);

        for (int i = 0; i < 3; i++)
            await Send(client, new { type = "tools/call", toolId = "slow", parameters = new { } }, cts.Token);

        // The third request is refused immediately, while the first two are still running.
        var refusal = await Read(client, cts.Token);
        Assert.Equal("too-many-inflight-requests", Reason(refusal));
        Assert.Equal(2, dispatcher.Calls);

        release.SetResult();
        Assert.True((await Read(client, cts.Token)).GetProperty("success").GetBoolean());
        Assert.True((await Read(client, cts.Token)).GetProperty("success").GetBoolean());

        cts.Cancel();
        await Task.WhenAny(serve, Task.Delay(1000));
    }

    [Fact]
    public async Task AnOversizedResultBecomesAnExplicitRejectionNotAnInternalError()
    {
        var big = "{\"data\":\"" + new string('x', McpFraming.MaxPayloadBytes) + "\"}";
        var dispatcher = new RecordingDispatcher((_, _, _, _) => Task.FromResult(ToolCallResult.Ok(big)));
        var server = Server(dispatcher);
        var (serverSide, client) = ChannelStream.CreatePair();
        using var cts = Timeout();
        var serve = server.ServeAsync(serverSide, () => true, "CALLER", cts.Token);

        await Send(client, new { type = "tools/call", toolId = "big", parameters = new { } }, cts.Token);
        var result = await Read(client, cts.Token);

        Assert.False(result.GetProperty("success").GetBoolean());
        Assert.Equal("response-too-large", Reason(result));

        cts.Cancel();
        await Task.WhenAny(serve, Task.Delay(1000));
    }

    [Fact]
    public async Task DisconnectEndsTheSessionAndUnblocksAPendingApproval()
    {
        var dispatcher = new RecordingDispatcher();
        var server = Server(dispatcher, new() { ["Elicitation:TtlSeconds"] = "60" });
        var (serverSide, client) = ChannelStream.CreatePair();
        using var cts = Timeout();
        var serve = server.ServeAsync(serverSide, () => true, "CALLER", cts.Token);

        await Send(client, new { type = "tools/call", toolId = "gated", parameters = new { } }, cts.Token);
        await Read(client, cts.Token);                 // elicitation/request is now pending

        cts.Cancel();                                  // service stopping / connection torn down
        await Task.WhenAny(serve, Task.Delay(6000));

        Assert.True(serve.IsCompleted, "session did not end promptly");
        Assert.Empty(dispatcher.Replies);
    }
}

public class PipePrincipalTests
{
    private const string DomainUser = "S-1-5-21-1111111111-2222222222-3333333333-1105";

    [Theory]
    [InlineData("S-1-1-0")]            // Everyone
    [InlineData("S-1-5-7")]            // Anonymous
    [InlineData("S-1-5-11")]           // Authenticated Users
    [InlineData("S-1-5-32-545")]       // BUILTIN\Users
    [InlineData("S-1-5-32-546")]       // BUILTIN\Guests
    [InlineData("S-1-5-2")]            // Network
    [InlineData("S-1-5-4")]            // Interactive
    [InlineData("S-1-5-21-1111111111-2222222222-3333333333-513")]  // Domain Users
    [InlineData("S-1-5-21-1111111111-2222222222-3333333333-514")]  // Domain Guests
    [InlineData("S-1-5-21-1111111111-2222222222-3333333333-515")]  // Domain Computers
    public void BroadPrincipalsAreRefusedAsPipeClients(string sid)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => PipePrincipals.Validate(new[] { DomainUser, sid }));
        Assert.Contains("too broad", ex.Message);
    }

    [Theory]
    [InlineData("")]
    [InlineData("Everyone")]
    [InlineData("S-1-")]
    [InlineData("not-a-sid")]
    [InlineData("S-1-5-21-abc")]
    [InlineData("S-1-5-21-\uFF11\uFF12\uFF13")]       // fullwidth digits: \d would match them
    [InlineData("S-1-5-21-\u0661\u0662")]             // Arabic-Indic digits
    [InlineData("S-1-5-21-1-2-3-1001\n")]
    public void MalformedSidsAreRefused(string sid) =>
        Assert.Throws<InvalidOperationException>(() => PipePrincipals.Validate(new[] { sid }));

    [Fact]
    public void AnEmptyListIsRefused() =>
        Assert.Throws<InvalidOperationException>(() => PipePrincipals.Validate(Array.Empty<string>()));

    [Fact]
    public void SpecificUsersAndGroupsAreAccepted() =>
        PipePrincipals.Validate(new[] { DomainUser, "S-1-5-21-1111111111-2222222222-3333333333-1200", "S-1-5-32-544" });
}

public class ApprovalPipeServeTests
{
    private const string ApproverSid = "S-1-5-21-1-2-3-2001";

    private static (ApprovalPipeServer server, ElicitationRouter router) Build(params string[] approvers)
    {
        var cfg = new Dictionary<string, string?>();
        for (int i = 0; i < approvers.Length; i++) cfg[$"Elicitation:ApproverSids:{i}"] = approvers[i];
        var config = new ConfigurationBuilder().AddInMemoryCollection(cfg).Build();
        var router = new ElicitationRouter(NullLogger<ElicitationRouter>.Instance);
        return (new ApprovalPipeServer(new PipeSecurityFactory(config, NullLogger<PipeSecurityFactory>.Instance),
            router, config, NullLogger<ApprovalPipeServer>.Instance), router);
    }

    private static Task Send(Stream s, string raw, CancellationToken ct) => McpFraming.WriteFrameAsync(s, raw, ct);

    private static string Reply(string corr, string hash, string tool, string approved = "true", string extra = "") =>
        $"{{\"correlationId\":\"{corr}\",\"paramHash\":\"{hash}\",\"toolId\":\"{tool}\",\"approved\":{approved}{extra}}}";

    [Fact]
    public async Task ApproverIdentityComesFromTheConnectionNeverFromTheMessage()
    {
        var (server, router) = Build(ApproverSid);
        var (serverSide, client) = ChannelStream.CreatePair();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var serve = server.ServeApproverAsync(serverSide, () => true, ApproverSid, cts.Token);

        var pending = router.RequestAsync(new ElicitationContext("c1", "tool-a", "CALLER", "h1"), TimeSpan.FromSeconds(10), cts.Token);
        await McpFraming.ReadFrameAsync(client, TimeSpan.FromSeconds(5), cts.Token);   // approval/request

        // The reply claims to be somebody else; that field must be ignored.
        await Send(client, Reply("c1", "h1", "tool-a", extra: ",\"decidedBySid\":\"S-1-5-21-FORGED\",\"approverSid\":\"S-1-5-21-FORGED\""), cts.Token);
        var decided = await pending.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(ApproverSid, decided.DecidedBySid);
        cts.Cancel();
        await Task.WhenAny(serve, Task.Delay(1000));
    }

    [Fact]
    public async Task TheApproverIsShownTheExactToolCallerAndParametersBeingApproved()
    {
        var (server, router) = Build(ApproverSid);
        var (serverSide, client) = ChannelStream.CreatePair();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var serve = server.ServeApproverAsync(serverSide, () => true, ApproverSid, cts.Token);

        var parameters = new Dictionary<string, string> { ["ServiceName"] = "Spooler", ["Action"] = "Stop" };
        _ = router.RequestAsync(new ElicitationContext("c9", "set-windows-service-state", "S-1-5-21-CALLER", "h9", parameters),
            TimeSpan.FromSeconds(5), cts.Token);

        var frame = await McpFraming.ReadFrameAsync(client, TimeSpan.FromSeconds(5), cts.Token);
        var root = System.Text.Json.JsonDocument.Parse(frame!).RootElement;

        Assert.Equal("approval/request", root.GetProperty("type").GetString());
        Assert.Equal("set-windows-service-state", root.GetProperty("toolId").GetString());
        Assert.Equal("S-1-5-21-CALLER", root.GetProperty("callerSid").GetString());
        Assert.Equal("h9", root.GetProperty("paramHash").GetString());
        var shown = root.GetProperty("parameters").EnumerateObject().ToDictionary(p => p.Name, p => p.Value.GetString()!);
        Assert.Equal(parameters, shown);

        cts.Cancel();
        await Task.WhenAny(serve, Task.Delay(1000));
    }

    [Fact]
    public async Task ABacklogEntryIsShownWithItsParametersToo()
    {
        var (server, router) = Build(ApproverSid);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));

        // Requested BEFORE any approver is connected.
        _ = router.RequestAsync(new ElicitationContext("c10", "tool-a", "CALLER", "h10",
            new Dictionary<string, string> { ["Name"] = "x" }), TimeSpan.FromSeconds(10), cts.Token);

        var (serverSide, client) = ChannelStream.CreatePair();
        var serve = server.ServeApproverAsync(serverSide, () => true, ApproverSid, cts.Token);

        var frame = await McpFraming.ReadFrameAsync(client, TimeSpan.FromSeconds(5), cts.Token);
        var root = System.Text.Json.JsonDocument.Parse(frame!).RootElement;
        Assert.Equal("x", root.GetProperty("parameters").GetProperty("Name").GetString());

        cts.Cancel();
        await Task.WhenAny(serve, Task.Delay(1000));
    }

    [Fact]
    public async Task AReplyFromAConnectionOutsideTheApproverListIsIgnored()
    {
        var (server, router) = Build(ApproverSid);
        var (serverSide, client) = ChannelStream.CreatePair();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        // e.g. the broker's own service identity, which the ACL always admits.
        var serve = server.ServeApproverAsync(serverSide, () => true, "S-1-5-21-1-2-3-9999", cts.Token);

        var pending = router.RequestAsync(new ElicitationContext("c2", "tool-a", "CALLER", "h2"), TimeSpan.FromMilliseconds(800), cts.Token);
        await McpFraming.ReadFrameAsync(client, TimeSpan.FromSeconds(5), cts.Token);
        await Send(client, Reply("c2", "h2", "tool-a"), cts.Token);

        // The pending request was not consumed or resolved: it simply times out.
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
        cts.Cancel();
        await Task.WhenAny(serve, Task.Delay(1000));
    }

    [Theory]
    [InlineData("\"yes\"")]
    [InlineData("1")]
    [InlineData("null")]
    public async Task ANonBooleanApprovedDoesNotResolveThePendingRequest(string approved)
    {
        var (server, router) = Build(ApproverSid);
        var (serverSide, client) = ChannelStream.CreatePair();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var serve = server.ServeApproverAsync(serverSide, () => true, ApproverSid, cts.Token);

        var pending = router.RequestAsync(new ElicitationContext("c3", "tool-a", "CALLER", "h3"), TimeSpan.FromMilliseconds(800), cts.Token);
        await McpFraming.ReadFrameAsync(client, TimeSpan.FromSeconds(5), cts.Token);
        await Send(client, Reply("c3", "h3", "tool-a", approved), cts.Token);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
        cts.Cancel();
        await Task.WhenAny(serve, Task.Delay(1000));
    }

    [Fact]
    public async Task MalformedApproverFramesDoNotApproveAnythingAndEndTheSession()
    {
        var (server, router) = Build(ApproverSid);
        var (serverSide, client) = ChannelStream.CreatePair();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var serve = server.ServeApproverAsync(serverSide, () => true, ApproverSid, cts.Token);

        var pending = router.RequestAsync(new ElicitationContext("c4", "tool-a", "CALLER", "h4"), TimeSpan.FromMilliseconds(800), cts.Token);
        await McpFraming.ReadFrameAsync(client, TimeSpan.FromSeconds(5), cts.Token);
        await Send(client, "{ not json", cts.Token);

        await serve.WaitAsync(TimeSpan.FromSeconds(5));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
    }

    [Fact]
    public async Task AnApproverWithoutAnIdentityIsRefused()
    {
        var (server, router) = Build(ApproverSid);
        var (serverSide, client) = ChannelStream.CreatePair();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));

        await server.ServeApproverAsync(serverSide, () => true, "", cts.Token).WaitAsync(TimeSpan.FromSeconds(5));

        Assert.False(router.HasApprovers);
    }

    [Fact]
    public async Task ReplyWithTheWrongToolOrHashDoesNotResolve()
    {
        var (server, router) = Build(ApproverSid);
        var (serverSide, client) = ChannelStream.CreatePair();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var serve = server.ServeApproverAsync(serverSide, () => true, ApproverSid, cts.Token);

        var pending = router.RequestAsync(new ElicitationContext("c5", "tool-a", "CALLER", "h5"), TimeSpan.FromSeconds(3), cts.Token);
        await McpFraming.ReadFrameAsync(client, TimeSpan.FromSeconds(5), cts.Token);

        await Send(client, Reply("c5", "h5", "tool-b"), cts.Token);       // wrong tool
        await Send(client, Reply("c5", "other", "tool-a"), cts.Token);    // wrong hash
        Assert.False(pending.IsCompleted);

        await Send(client, Reply("c5", "h5", "tool-a"), cts.Token);       // the right one
        Assert.True((await pending.WaitAsync(TimeSpan.FromSeconds(5))).Approved);

        cts.Cancel();
        await Task.WhenAny(serve, Task.Delay(1000));
    }
}


/// <summary>Reads work (backed by a channel pair); writes never complete until cancelled, like a client that stopped reading.</summary>
internal sealed class WriteStallStream : Stream
{
    private readonly Stream _inner;
    public int WriteAttempts;
    public WriteStallStream(Stream inner) => _inner = inner;

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) => _inner.ReadAsync(buffer, ct);
    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
    {
        Interlocked.Increment(ref WriteAttempts);
        await Task.Delay(Timeout.Infinite, ct);
    }
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override bool CanRead => true;
    public override bool CanWrite => true;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
}

public class TransportResourceLimitTests
{
    [Fact]
    public async Task AClientThatStopsReadingIsDisconnectedAfterTheWriteTimeout()
    {
        var dispatcher = new RecordingDispatcher();
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Pipe:WriteTimeoutSeconds"] = "1", ["Pipe:FrameTimeoutSeconds"] = "5"
        }).Build();
        var server = new NamedPipeServer(new PipeSecurityFactory(config, NullLogger<PipeSecurityFactory>.Instance),
            dispatcher, new ElicitationRouter(NullLogger<ElicitationRouter>.Instance), config, NullLogger<NamedPipeServer>.Instance);

        var (serverSide, client) = ChannelStream.CreatePair();
        var stalled = new WriteStallStream(serverSide);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

        var serve = server.ServeAsync(stalled, () => true, "CALLER", cts.Token);
        await McpFraming.WriteFrameAsync(client, "{\"toolId\":\"echo\"}", cts.Token);

        // The answer can never be delivered; the session must end by itself rather than hold its slot forever.
        await serve.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(1, dispatcher.Calls);
        Assert.True(stalled.WriteAttempts >= 1);
    }

    [Fact]
    public void ACallerCannotHoldMoreConnectionsThanItsShare()
    {
        var limiter = new PerCallerConnectionLimiter(maxPerCaller: 2);

        Assert.True(limiter.TryAcquire("A"));
        Assert.True(limiter.TryAcquire("A"));
        Assert.False(limiter.TryAcquire("A"));
        Assert.True(limiter.TryAcquire("B"));   // other callers are unaffected

        limiter.Release("A");
        Assert.True(limiter.TryAcquire("A"));
    }

    [Fact]
    public void ReleasingMoreThanWasAcquiredNeverGoesNegative()
    {
        var limiter = new PerCallerConnectionLimiter(maxPerCaller: 1);
        limiter.Release("A"); limiter.Release("A");

        Assert.True(limiter.TryAcquire("A"));
        Assert.False(limiter.TryAcquire("A"));
    }

    [Fact]
    public async Task ConcurrentAcquiresNeverExceedTheCap()
    {
        var limiter = new PerCallerConnectionLimiter(maxPerCaller: 5);
        int granted = 0;

        await Task.WhenAll(Enumerable.Range(0, 200).Select(_ => Task.Run(() =>
        {
            if (limiter.TryAcquire("A")) Interlocked.Increment(ref granted);
        })));

        Assert.Equal(5, granted);
    }

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    public void ABlankIdentityIsNeverGrantedAConnection(string sid) =>
        Assert.False(new PerCallerConnectionLimiter(5).TryAcquire(sid));
}
