using System.Text.Json;
using Broker.ApproverCli;
using Broker.McpAdapter;
using Xunit;

namespace Broker.Tests;

public class McpAdapterTests
{
    private static string GetRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "mcp-broker.sln")))
        {
            dir = dir.Parent;
        }
        return dir?.FullName ?? throw new InvalidOperationException("Could not locate repo root containing mcp-broker.sln");
    }

    [Fact]
    public async Task McpAdapterInitializeReturnsExpectedServerInfoAndProtocolVersion()
    {
        var manifestPath = Path.Combine(GetRepoRoot(), "policy", "manifest.json");
        var server = new McpServer(manifestPath);

        const string initRequest = """
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "test-client", "version": "1.0" }
            }
        }
        """;

        var responseJson = await server.ProcessMessageAsync(initRequest);
        Assert.NotNull(responseJson);

        using var doc = JsonDocument.Parse(responseJson);
        var root = doc.RootElement;

        Assert.Equal("2.0", root.GetProperty("jsonrpc").GetString());
        Assert.Equal(1, root.GetProperty("id").GetInt32());

        var result = root.GetProperty("result");
        Assert.Equal("2024-11-05", result.GetProperty("protocolVersion").GetString());

        var serverInfo = result.GetProperty("serverInfo");
        Assert.Equal("windows-server-mcp", serverInfo.GetProperty("name").GetString());
        Assert.Equal("1.0.0", serverInfo.GetProperty("version").GetString());
    }

    [Fact]
    public async Task McpAdapterInitializedNotificationProducesNoResponse()
    {
        var manifestPath = Path.Combine(GetRepoRoot(), "policy", "manifest.json");
        var server = new McpServer(manifestPath);

        const string notify = """
        {
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }
        """;

        var responseJson = await server.ProcessMessageAsync(notify);
        Assert.Null(responseJson);
    }

    [Fact]
    public async Task McpAdapterToolsListEnumeratesManifestWithSchemaDraft07()
    {
        var manifestPath = Path.Combine(GetRepoRoot(), "policy", "manifest.json");
        var server = new McpServer(manifestPath);

        const string listRequest = """
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }
        """;

        var responseJson = await server.ProcessMessageAsync(listRequest);
        Assert.NotNull(responseJson);

        using var doc = JsonDocument.Parse(responseJson);
        var root = doc.RootElement;

        Assert.Equal(2, root.GetProperty("id").GetInt32());
        var tools = root.GetProperty("result").GetProperty("tools");
        Assert.True(tools.GetArrayLength() > 0);

        // Verify list-jea-endpoints tool structure
        bool foundTool = false;
        foreach (var t in tools.EnumerateArray())
        {
            if (t.GetProperty("name").GetString() == "list-jea-endpoints")
            {
                foundTool = true;
                Assert.True(t.TryGetProperty("description", out _));
                var schema = t.GetProperty("inputSchema");
                Assert.Equal("object", schema.GetProperty("type").GetString());
                Assert.True(schema.TryGetProperty("properties", out _));
                break;
            }
        }
        Assert.True(foundTool, "Expected list-jea-endpoints tool in tools/list");
    }

    [Fact]
    public async Task McpAdapterToolsCallDispatchesToBrokerAndReturnsFormattedMcpResult()
    {
        var manifestPath = Path.Combine(GetRepoRoot(), "policy", "manifest.json");
        string? capturedTool = null;
        Dictionary<string, string>? capturedParams = null;

        var server = new McpServer(manifestPath, dispatcher: (toolId, parameters, ct) =>
        {
            capturedTool = toolId;
            capturedParams = parameters;
            return Task.FromResult(new ToolExecutionResult(true, null, "{\"ping\":\"pong\"}"));
        });

        const string callRequest = """
        {
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tools/call",
            "params": {
                "name": "ping-broker",
                "arguments": {
                    "echo": "hello"
                }
            }
        }
        """;

        var responseJson = await server.ProcessMessageAsync(callRequest);
        Assert.NotNull(responseJson);

        Assert.Equal("ping-broker", capturedTool);
        Assert.NotNull(capturedParams);
        Assert.Equal("hello", capturedParams["echo"]);

        using var doc = JsonDocument.Parse(responseJson);
        var root = doc.RootElement;
        Assert.Equal(42, root.GetProperty("id").GetInt32());

        var result = root.GetProperty("result");
        Assert.False(result.GetProperty("isError").GetBoolean());

        var content = result.GetProperty("content");
        Assert.Equal(1, content.GetArrayLength());
        Assert.Equal("text", content[0].GetProperty("type").GetString());
        Assert.Equal("{\"ping\":\"pong\"}", content[0].GetProperty("text").GetString());
    }

    [Fact]
    public async Task McpAdapterToolsCallRejectionTranslatesToIsErrorTrue()
    {
        var manifestPath = Path.Combine(GetRepoRoot(), "policy", "manifest.json");
        var server = new McpServer(manifestPath, dispatcher: (toolId, parameters, ct) =>
        {
            return Task.FromResult(new ToolExecutionResult(false, "policy-resource-denied", "Path outside allowlist"));
        });

        const string callRequest = """
        {
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {
                "name": "get-broker-list-directory",
                "arguments": {
                    "Path": "C:\\Windows\\System32"
                }
            }
        }
        """;

        var responseJson = await server.ProcessMessageAsync(callRequest);
        Assert.NotNull(responseJson);

        using var doc = JsonDocument.Parse(responseJson);
        var root = doc.RootElement;
        Assert.Equal(99, root.GetProperty("id").GetInt32());

        var result = root.GetProperty("result");
        Assert.True(result.GetProperty("isError").GetBoolean());

        var content = result.GetProperty("content");
        var text = content[0].GetProperty("text").GetString();
        Assert.Contains("Tool call rejected: policy-resource-denied", text);
        Assert.Contains("Path outside allowlist", text);
    }

    [Fact]
    public async Task McpAdapterHandlesInvalidJsonWithParseError()
    {
        var manifestPath = Path.Combine(GetRepoRoot(), "policy", "manifest.json");
        var server = new McpServer(manifestPath);

        var responseJson = await server.ProcessMessageAsync("not json at all");
        Assert.NotNull(responseJson);

        using var doc = JsonDocument.Parse(responseJson);
        var root = doc.RootElement;
        var error = root.GetProperty("error");
        Assert.Equal(-32700, error.GetProperty("code").GetInt32());
    }

    [Fact]
    public async Task McpAdapterHandlesUnknownMethodWithMethodNotFound()
    {
        var manifestPath = Path.Combine(GetRepoRoot(), "policy", "manifest.json");
        var server = new McpServer(manifestPath);

        const string unknownRequest = """
        {
            "jsonrpc": "2.0",
            "id": 105,
            "method": "someUnknownMethod",
            "params": {}
        }
        """;

        var responseJson = await server.ProcessMessageAsync(unknownRequest);
        Assert.NotNull(responseJson);

        using var doc = JsonDocument.Parse(responseJson);
        var root = doc.RootElement;
        Assert.Equal(105, root.GetProperty("id").GetInt32());
        var error = root.GetProperty("error");
        Assert.Equal(-32601, error.GetProperty("code").GetInt32());
    }

    [Fact]
    public async Task McpAdapterStdioFramingSupportsMultiplePipelinedMessages()
    {
        var manifestPath = Path.Combine(GetRepoRoot(), "policy", "manifest.json");
        var server = new McpServer(manifestPath, dispatcher: (toolId, parameters, ct) =>
        {
            return Task.FromResult(new ToolExecutionResult(true, null, "{\"count\":1}"));
        });

        var input = """
        {"jsonrpc":"2.0","id":1,"method":"ping"}
        {"jsonrpc":"2.0","method":"notifications/initialized"}
        {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ping-broker","arguments":{}}}
        """;

        using var reader = new StringReader(input);
        using var writer = new StringWriter();

        await server.RunAsync(reader, writer);

        var lines = writer.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        Assert.Equal(2, lines.Length); // Notification produces no response, so exactly 2 lines

        using var doc1 = JsonDocument.Parse(lines[0]);
        Assert.Equal(1, doc1.RootElement.GetProperty("id").GetInt32());

        using var doc2 = JsonDocument.Parse(lines[1]);
        Assert.Equal(2, doc2.RootElement.GetProperty("id").GetInt32());
        Assert.False(doc2.RootElement.GetProperty("result").GetProperty("isError").GetBoolean());
    }

    [Fact]
    public async Task ApproverCliParsesRequestAndSubmitsApprovalReply()
    {
        var (serverStream, clientStream) = ChannelStream.CreatePair();
        bool prompterCalled = false;

        var client = new ApproverClient("testPipe", request =>
        {
            prompterCalled = true;
            Assert.Equal("corr-456", request.CorrelationId);
            Assert.Equal("set-broker-scheduled-task-state", request.ToolId);
            Assert.Equal("S-1-5-21-test-caller", request.CallerSid);
            Assert.Equal("MyTask", request.Parameters["TaskName"]);
            return Task.FromResult(true);
        });

        var requestJson = JsonSerializer.Serialize(new
        {
            type = "approval/request",
            correlationId = "corr-456",
            toolId = "set-broker-scheduled-task-state",
            callerSid = "S-1-5-21-test-caller",
            paramHash = "hash789",
            parameters = new Dictionary<string, string> { ["TaskName"] = "MyTask" },
            expiresUtc = DateTime.UtcNow.AddMinutes(5)
        });

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        var serverTask = Task.Run(async () =>
        {
            await Broker.Transport.McpFraming.WriteFrameAsync(serverStream, requestJson, cts.Token);
            var replyJson = await Broker.Transport.McpFraming.ReadFrameAsync(serverStream, TimeSpan.FromSeconds(5), cts.Token);
            return replyJson;
        });

        using var input = new StringReader("");
        using var output = new StringWriter();

        bool isConnected = true;
        var clientTask = Task.Run(async () =>
        {
            await client.RunAsync(clientStream, () => isConnected, input, output, cts.Token);
        });

        var replyJson = await serverTask;
        Assert.NotNull(replyJson);

        using var doc = JsonDocument.Parse(replyJson);
        var root = doc.RootElement;
        Assert.Equal("corr-456", root.GetProperty("correlationId").GetString());
        Assert.Equal("hash789", root.GetProperty("paramHash").GetString());
        Assert.Equal("set-broker-scheduled-task-state", root.GetProperty("toolId").GetString());
        Assert.True(root.GetProperty("approved").GetBoolean());
        Assert.True(prompterCalled);

        isConnected = false;
        cts.Cancel();
        try { await clientTask; } catch { }
    }
}
