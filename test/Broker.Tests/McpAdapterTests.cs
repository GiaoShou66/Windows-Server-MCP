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

        // Parameterised tools must expose their manifest parameters. The manifest stores
        // "parameters" as an array; the adapter used to read it as an object and silently
        // emitted properties: {} / required: [] for all 62 tools.
        var byName = tools.EnumerateArray().ToDictionary(t => t.GetProperty("name").GetString()!);

        var adUser = byName["query-ad-user"].GetProperty("inputSchema");
        Assert.Equal("string", PropertyType(adUser, "SamAccountName"));
        Assert.Equal(new[] { "SamAccountName" }, RequiredOf(adUser));

        var task = byName["set-scheduled-task-state"].GetProperty("inputSchema");
        Assert.Equal("string", PropertyType(task, "TaskPath"));
        Assert.Equal("string", PropertyType(task, "TaskName"));
        Assert.Equal("boolean", PropertyType(task, "Enabled"));
        Assert.Equal(new[] { "TaskPath", "TaskName", "Enabled" }, RequiredOf(task));

        // Optional int parameter: typed "integer" and absent from "required".
        var transcripts = byName["summarize-transcript-logs"].GetProperty("inputSchema");
        Assert.Equal("integer", PropertyType(transcripts, "DaysBack"));
        Assert.Empty(RequiredOf(transcripts));

        // A parameterless tool keeps an empty schema.
        var endpoints = byName["list-jea-endpoints"].GetProperty("inputSchema");
        Assert.Empty(endpoints.GetProperty("properties").EnumerateObject());
        Assert.Empty(RequiredOf(endpoints));
    }

    /// <summary>
    /// tools/list must mirror the manifest exactly: every declared parameter is advertised,
    /// nothing is invented, the required set matches, and every advertised type is a JSON
    /// Schema primitive. The manifest's own type names ("int", "bool", "enum") are not valid
    /// JSON Schema, and a client that validates inputSchema rejects the whole tool list on one.
    /// </summary>
    [Fact]
    public async Task McpAdapterToolsListMirrorsEveryManifestParameterWithValidJsonSchemaTypes()
    {
        var manifestPath = Path.Combine(GetRepoRoot(), "policy", "manifest.json");
        var server = new McpServer(manifestPath);

        var responseJson = await server.ProcessMessageAsync("""{"jsonrpc":"2.0","id":3,"method":"tools/list"}""");
        Assert.NotNull(responseJson);

        using var doc = JsonDocument.Parse(responseJson);
        var listed = doc.RootElement.GetProperty("result").GetProperty("tools")
            .EnumerateArray().ToDictionary(t => t.GetProperty("name").GetString()!);

        using var manifest = JsonDocument.Parse(File.ReadAllText(manifestPath));
        var jsonSchemaTypes = new HashSet<string> { "string", "integer", "boolean" };
        int manifestTools = 0, manifestParameters = 0;

        foreach (var tool in manifest.RootElement.GetProperty("tools").EnumerateArray())
        {
            if (tool.TryGetProperty("revoked", out var revoked) && revoked.GetBoolean()) continue;
            manifestTools++;

            var toolId = tool.GetProperty("toolId").GetString()!;
            Assert.True(listed.ContainsKey(toolId), $"tools/list is missing '{toolId}'");
            var schema = listed[toolId].GetProperty("inputSchema");

            var declared = tool.GetProperty("parameters").EnumerateArray().ToList();
            manifestParameters += declared.Count;

            Assert.Equal(
                declared.Select(p => p.GetProperty("name").GetString()!).OrderBy(n => n, StringComparer.Ordinal).ToArray(),
                schema.GetProperty("properties").EnumerateObject().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal).ToArray());

            Assert.Equal(
                declared.Where(p => p.TryGetProperty("required", out var r) && r.GetBoolean())
                    .Select(p => p.GetProperty("name").GetString()!).ToArray(),
                RequiredOf(schema));

            foreach (var property in schema.GetProperty("properties").EnumerateObject())
                Assert.Contains(property.Value.GetProperty("type").GetString()!, jsonSchemaTypes);
        }

        Assert.Equal(manifestTools, listed.Count);
        Assert.True(manifestParameters > 0, "Fixture manifest should declare at least one parameter");
    }

    /// <summary>
    /// A malformed parameter entry must not truncate discovery: HandleToolsList swallows
    /// exceptions, so a throw while reading one tool would silently drop every later tool.
    /// </summary>
    [Fact]
    public async Task McpAdapterToolsListSkipsMalformedParameterEntriesWithoutDroppingTools()
    {
        var manifestPath = Path.Combine(Path.GetTempPath(), $"mcp-test-adapter-manifest-{Guid.NewGuid():N}.json");
        File.WriteAllText(manifestPath, """
        {
          "tools": [
            {
              "toolId": "odd-tool",
              "parameters": [
                "not-an-object",
                { "type": "string" },
                { "name": 7 },
                { "name": "" },
                { "name": "Loose", "type": 5, "required": "true", "description": 9 },
                { "name": "Flag", "type": "bool", "required": true },
                { "name": "Flag", "type": "bool", "required": true },
                { "name": "Mode", "type": "enum", "required": false, "description": "How to run" }
              ]
            },
            { "toolId": "object-shaped-tool", "parameters": { "Legacy": { "type": "string" } } },
            { "toolId": "later-tool", "parameters": [] }
          ]
        }
        """);

        try
        {
            var server = new McpServer(manifestPath);
            var responseJson = await server.ProcessMessageAsync("""{"jsonrpc":"2.0","id":4,"method":"tools/list"}""");
            Assert.NotNull(responseJson);

            using var doc = JsonDocument.Parse(responseJson);
            var listed = doc.RootElement.GetProperty("result").GetProperty("tools")
                .EnumerateArray().ToDictionary(t => t.GetProperty("name").GetString()!);

            Assert.Equal(new[] { "later-tool", "object-shaped-tool", "odd-tool" },
                listed.Keys.OrderBy(k => k, StringComparer.Ordinal).ToArray());

            var odd = listed["odd-tool"].GetProperty("inputSchema");
            Assert.Equal(new[] { "Flag", "Loose", "Mode" },
                odd.GetProperty("properties").EnumerateObject().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal).ToArray());

            // Non-string type falls back to "string"; a non-boolean "required" is not required.
            Assert.Equal("string", PropertyType(odd, "Loose"));
            Assert.False(odd.GetProperty("properties").GetProperty("Loose").TryGetProperty("description", out _));
            Assert.Equal("boolean", PropertyType(odd, "Flag"));
            Assert.Equal("string", PropertyType(odd, "Mode"));
            Assert.Equal("How to run", odd.GetProperty("properties").GetProperty("Mode").GetProperty("description").GetString());

            // A duplicated parameter is advertised once and listed once in "required".
            Assert.Equal(new[] { "Flag" }, RequiredOf(odd));

            // An object-shaped "parameters" value is not the manifest format; it yields no properties.
            Assert.Empty(listed["object-shaped-tool"].GetProperty("inputSchema").GetProperty("properties").EnumerateObject());
        }
        finally
        {
            try { File.Delete(manifestPath); } catch { }
        }
    }

    private static string? PropertyType(JsonElement inputSchema, string parameterName) =>
        inputSchema.GetProperty("properties").GetProperty(parameterName).GetProperty("type").GetString();

    private static string[] RequiredOf(JsonElement inputSchema) =>
        inputSchema.GetProperty("required").EnumerateArray().Select(r => r.GetString()!).ToArray();

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

    /// <summary>
    /// tools/list advertises bool/int parameters as JSON boolean/integer, so clients send
    /// typed values. They must reach the broker as the exact strings its allowlists expect,
    /// and an explicit JSON null (how some clients encode "optional, not supplied") must be
    /// dropped rather than forwarded as the literal string "null".
    /// </summary>
    [Fact]
    public async Task McpAdapterToolsCallFlattensTypedArgumentsAndDropsNulls()
    {
        var manifestPath = Path.Combine(GetRepoRoot(), "policy", "manifest.json");
        Dictionary<string, string>? captured = null;

        var server = new McpServer(manifestPath, dispatcher: (toolId, parameters, ct) =>
        {
            captured = parameters;
            return Task.FromResult(new ToolExecutionResult(true, null, "{}"));
        });

        const string callRequest = """
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "set-scheduled-task-state",
                "arguments": {
                    "TaskPath": "\\",
                    "TaskName": null,
                    "Enabled": false,
                    "DaysBack": 7,
                    "Flag": true
                }
            }
        }
        """;

        var responseJson = await server.ProcessMessageAsync(callRequest);
        Assert.NotNull(responseJson);
        Assert.NotNull(captured);

        Assert.Equal("\\", captured["TaskPath"]);
        Assert.Equal("false", captured["Enabled"]);
        Assert.Equal("true", captured["Flag"]);
        Assert.Equal("7", captured["DaysBack"]);
        Assert.False(captured.ContainsKey("TaskName"));
        Assert.DoesNotContain("null", captured.Values);
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

    /// <summary>
    /// The approver CLI shows the broker-reported taint state of the caller. A broker that
    /// does not send the field must surface as "unknown" (null), never as "not tainted".
    /// </summary>
    [Theory]
    [InlineData(true, true)]
    [InlineData(false, false)]
    [InlineData(null, null)]
    public async Task ApproverCliSurfacesBrokerReportedCallerTaint(bool? sent, bool? expected)
    {
        var (serverStream, clientStream) = ChannelStream.CreatePair();
        bool? seen = false;
        bool prompterCalled = false;

        var client = new ApproverClient("testPipe", request =>
        {
            prompterCalled = true;
            seen = request.CallerTainted;
            return Task.FromResult(false);
        });

        var payload = new Dictionary<string, object?>
        {
            ["type"] = "approval/request",
            ["correlationId"] = "corr-taint",
            ["toolId"] = "set-ad-user-enabled",
            ["callerSid"] = "S-1-5-21-test-caller",
            ["paramHash"] = "hash-taint",
            ["parameters"] = new Dictionary<string, string> { ["SamAccountName"] = "jlee" },
            ["expiresUtc"] = DateTime.UtcNow.AddMinutes(5)
        };
        if (sent.HasValue) payload["callerTainted"] = sent.Value;

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        var serverTask = Task.Run(async () =>
        {
            await Broker.Transport.McpFraming.WriteFrameAsync(serverStream, JsonSerializer.Serialize(payload), cts.Token);
            return await Broker.Transport.McpFraming.ReadFrameAsync(serverStream, TimeSpan.FromSeconds(5), cts.Token);
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
        Assert.True(prompterCalled);
        Assert.Equal(expected, seen);

        isConnected = false;
        cts.Cancel();
        try { await clientTask; } catch { }
    }

    [Fact]
    public void ApproverCardTaintLineNeverDefaultsToNoAndFitsTheCard()
    {
        Assert.StartsWith("YES", ApproverClient.DescribeTaint(true));
        Assert.Equal("no", ApproverClient.DescribeTaint(false));
        Assert.StartsWith("unknown", ApproverClient.DescribeTaint(null));

        // The card is 80 columns wide and the "Caller taint:   " label takes 16 of them.
        Assert.True(ApproverClient.DescribeTaint(true).Length <= 64);
    }
}
