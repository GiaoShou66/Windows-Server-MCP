using System.IO.Pipes;
using System.Security.Principal;
using System.Text.Json;
using Broker.Transport;

namespace Broker.ApproverCli;

public sealed record ApprovalRequest(
    string CorrelationId,
    string ToolId,
    string CallerSid,
    string ParamHash,
    Dictionary<string, string> Parameters,
    DateTime ExpiresUtc,
    bool? CallerTainted = null);

public delegate Task<bool> ApprovalDecisionPrompter(ApprovalRequest request);

public sealed class ApproverClient
{
    private readonly string _pipeName;
    private readonly ApprovalDecisionPrompter _prompter;

    public ApproverClient(string pipeName = "McpBroker.Approvals", ApprovalDecisionPrompter? prompter = null)
    {
        _pipeName = pipeName;
        _prompter = prompter ?? DefaultConsolePrompter;
    }

    public async Task RunAsync(TextReader input, TextWriter output, CancellationToken ct = default)
    {
        var currentIdentity = WindowsIdentity.GetCurrent().User?.Value ?? "UNKNOWN";
        await output.WriteLineAsync($"[approver-cli] Connecting to approval pipe '\\\\.\\pipe\\{_pipeName}' as approver SID: {currentIdentity}");

        // Identification is declared explicitly: with no level the broker cannot read this
        // connection's SID until it has read data from the pipe, and it captures the approver
        // identity at connect time — so the connection was dropped. Identification lets the
        // broker see who the approver is without being able to act as them.
        using var client = new NamedPipeClientStream(
            ".", _pipeName, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
        await client.ConnectAsync(ct);
        await output.WriteLineAsync("[approver-cli] Connected. Waiting for authorization requests from MCP Broker...");

        await RunAsync(client, () => client.IsConnected, input, output, ct);
    }

    public async Task RunAsync(Stream stream, Func<bool> isConnected, TextReader input, TextWriter output, CancellationToken ct = default)
    {
        while (!ct.IsCancellationRequested && isConnected())
        {
            string? frame;
            try
            {
                frame = await McpFraming.ReadFrameAsync(stream, TimeSpan.FromSeconds(30), ct);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                continue;
            }

            if (frame is null)
            {
                await output.WriteLineAsync("[approver-cli] Approval pipe disconnected by server.");
                break;
            }

            using var doc = JsonDocument.Parse(frame);
            var root = doc.RootElement;
            var type = root.TryGetProperty("type", out var t) ? t.GetString() : null;

            if (type != "approval/request")
            {
                await output.WriteLineAsync($"[approver-cli] Ignoring unexpected message type: {type}");
                continue;
            }

            var correlationId = root.GetProperty("correlationId").GetString() ?? "";
            var toolId = root.GetProperty("toolId").GetString() ?? "";
            var callerSid = root.GetProperty("callerSid").GetString() ?? "";
            var paramHash = root.GetProperty("paramHash").GetString() ?? "";
            var expiresUtc = root.TryGetProperty("expiresUtc", out var exp) ? exp.GetDateTime() : DateTime.UtcNow.AddSeconds(60);

            var parameters = new Dictionary<string, string>();
            if (root.TryGetProperty("parameters", out var pObj) && pObj.ValueKind == JsonValueKind.Object)
            {
                foreach (var prop in pObj.EnumerateObject())
                {
                    parameters[prop.Name] = prop.Value.GetString() ?? prop.Value.GetRawText();
                }
            }

            // Reported by the broker from its own taint tracker, never by the caller. A broker
            // that predates the field omits it: that is shown as "unknown", never as "no".
            bool? callerTainted = null;
            if (root.TryGetProperty("callerTainted", out var taintElem) &&
                taintElem.ValueKind is JsonValueKind.True or JsonValueKind.False)
                callerTainted = taintElem.GetBoolean();

            var request = new ApprovalRequest(correlationId, toolId, callerSid, paramHash, parameters, expiresUtc, callerTainted);
            var approved = await _prompter(request);

            var replyJson = JsonSerializer.Serialize(new
            {
                correlationId = correlationId,
                paramHash = paramHash,
                approved = approved,
                toolId = toolId
            });

            await McpFraming.WriteFrameAsync(stream, replyJson, ct);
            await output.WriteLineAsync($"[approver-cli] Decision submitted: {(approved ? "APPROVED" : "DENIED")} (Tool: {toolId}, CorrelationId: {correlationId})");
        }
    }

    /// <summary>
    /// Card text for the caller's taint state. A tainted caller received output from a tool
    /// that can carry attacker-influenced text (AD attributes, host metadata, file contents)
    /// within the broker's taint window, so the request may be the result of prompt
    /// injection. The broker no longer refuses write-tier calls on taint; this line is how
    /// the approver learns of it.
    /// </summary>
    public static string DescribeTaint(bool? callerTainted) => callerTainted switch
    {
        true => "YES - read untrusted data recently; verify the target yourself",
        false => "no",
        null => "unknown (broker did not report it)"
    };

    private static async Task<bool> DefaultConsolePrompter(ApprovalRequest request)
    {
        await Console.Out.WriteLineAsync();
        await Console.Out.WriteLineAsync("================================================================================");
        await Console.Out.WriteLineAsync("                         [PENDING APPROVAL REQUEST]");
        await Console.Out.WriteLineAsync("================================================================================");
        await Console.Out.WriteLineAsync($"CorrelationId:  {request.CorrelationId}");
        await Console.Out.WriteLineAsync($"Tool ID:        {request.ToolId}");
        await Console.Out.WriteLineAsync($"Caller SID:     {request.CallerSid}");
        await Console.Out.WriteLineAsync($"Caller taint:   {DescribeTaint(request.CallerTainted)}");
        await Console.Out.WriteLineAsync($"Expires (UTC):  {request.ExpiresUtc:u}");
        await Console.Out.WriteLineAsync("Parameters:");
        foreach (var (k, v) in request.Parameters)
        {
            await Console.Out.WriteLineAsync($"  {k,-20}: {v}");
        }
        await Console.Out.WriteLineAsync("================================================================================");
        await Console.Out.WriteAsync("Authorize execution? [y/N]: ");

        var answer = await Console.In.ReadLineAsync();
        var approved = !string.IsNullOrWhiteSpace(answer) &&
                       (answer.Trim().Equals("y", StringComparison.OrdinalIgnoreCase) ||
                        answer.Trim().Equals("yes", StringComparison.OrdinalIgnoreCase));
        return approved;
    }
}

