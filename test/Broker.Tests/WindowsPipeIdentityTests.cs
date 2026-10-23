using System.IO.Pipes;
using System.Security.Principal;
using System.Text.Json;
using Broker.Core;
using Broker.Transport;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Broker.Tests;

/// <summary>
/// Real named pipes, real ACLs, real impersonation (RunAsClient). These can only run on Windows, so they
/// are [WindowsOnlyFact]: skipped (and reported as skipped) elsewhere, executed by the Windows CI job.
/// They have NOT been executed by the author of this revision, which had no Windows host.
///
/// A same-user client can prove that the identity is taken from the connection rather than the
/// message, and that a listed SID is admitted. They cannot prove that a DIFFERENT, unlisted principal
/// is refused by the ACL: that needs a second account and remains a manual / integration-environment check.
/// </summary>
public class WindowsPipeIdentityTests
{
    private static string CurrentSid => WindowsIdentity.GetCurrent().User!.Value;

    private static IConfiguration Config(string pipe, string approvalPipe, string sid) =>
        new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Pipe:Name"] = pipe,
            ["Pipe:MaxInstances"] = "2",
            ["Pipe:AllowedSids:0"] = sid,
            ["Elicitation:ApprovalPipeName"] = approvalPipe,
            ["Elicitation:ApprovalPipeInstances"] = "2",
            ["Elicitation:ApproverSids:0"] = sid,
            ["Elicitation:RequireDistinctApprover"] = "true",
            ["Elicitation:TtlSeconds"] = "10"
        }).Build();

    [WindowsOnlyFact]
    public async Task CallerSidComesFromTheRealConnectionNotFromTheMessage()
    {
        var pipe = $"mcp-test-{Guid.NewGuid():N}";
        var config = Config(pipe, pipe + ".approvals", CurrentSid);
        string? seen = null;
        var dispatcher = new RecordingDispatcher((_, ctx, _, _) =>
        {
            seen = ctx.CallerSid;
            return Task.FromResult(ToolCallResult.Ok("{}"));
        });
        var server = new NamedPipeServer(new PipeSecurityFactory(config, NullLogger<PipeSecurityFactory>.Instance),
            dispatcher, new ElicitationRouter(NullLogger<ElicitationRouter>.Instance), config, NullLogger<NamedPipeServer>.Instance);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var run = server.RunAsync(cts.Token);

        await using var client = new NamedPipeClientStream(".", pipe, PipeDirection.InOut, PipeOptions.Asynchronous);
        await client.ConnectAsync(10_000, cts.Token);

        await McpFraming.WriteFrameAsync(client, JsonSerializer.Serialize(new
        {
            type = "tools/call", toolId = "echo", parameters = new { },
            callerSid = "S-1-5-21-FORGED", sid = "S-1-5-21-FORGED", decidedBySid = "S-1-5-21-FORGED"
        }), cts.Token);
        var frame = await McpFraming.ReadFrameAsync(client, TimeSpan.FromSeconds(10), cts.Token);

        Assert.NotNull(frame);
        Assert.True(JsonDocument.Parse(frame!).RootElement.GetProperty("success").GetBoolean());
        Assert.Equal(CurrentSid, seen);

        cts.Cancel();
        await Task.WhenAny(run, Task.Delay(3000));
    }

    [WindowsOnlyFact]
    public async Task ApproverSidComesFromTheRealApprovalConnectionNotFromTheMessage()
    {
        var pipe = $"mcp-test-{Guid.NewGuid():N}";
        var approvalPipe = pipe + ".approvals";
        var config = Config(pipe, approvalPipe, CurrentSid);
        var router = new ElicitationRouter(NullLogger<ElicitationRouter>.Instance);
        var approvals = new ApprovalPipeServer(new PipeSecurityFactory(config, NullLogger<PipeSecurityFactory>.Instance),
            router, config, NullLogger<ApprovalPipeServer>.Instance);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var run = approvals.RunAsync(cts.Token);

        await using var client = new NamedPipeClientStream(".", approvalPipe, PipeDirection.InOut, PipeOptions.Asynchronous);
        await client.ConnectAsync(10_000, cts.Token);

        var pending = router.RequestAsync(new ElicitationContext("corr-1", "tool-a", "S-1-5-21-SOMEONE-ELSE", "hash-1"),
            TimeSpan.FromSeconds(15), cts.Token);
        await McpFraming.ReadFrameAsync(client, TimeSpan.FromSeconds(10), cts.Token);   // approval/request

        await McpFraming.WriteFrameAsync(client, JsonSerializer.Serialize(new
        {
            correlationId = "corr-1", paramHash = "hash-1", toolId = "tool-a", approved = true,
            decidedBySid = "S-1-5-21-FORGED", approverSid = "S-1-5-21-FORGED"
        }), cts.Token);

        var reply = await pending.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(CurrentSid, reply.DecidedBySid);

        cts.Cancel();
        await Task.WhenAny(run, Task.Delay(3000));
    }

    [WindowsOnlyFact]
    public void ARealPipeAclIsBuiltForAListedSidAndRefusesAnEmptyOrBroadList()
    {
        var factory = new PipeSecurityFactory(Config("p", "a", CurrentSid), NullLogger<PipeSecurityFactory>.Instance);

        Assert.NotNull(factory.BuildFor(new[] { CurrentSid }));
        Assert.Throws<InvalidOperationException>(() => factory.BuildFor(Array.Empty<string>()));
        Assert.Throws<InvalidOperationException>(() => factory.BuildFor(new[] { "S-1-1-0" }));
    }
}
