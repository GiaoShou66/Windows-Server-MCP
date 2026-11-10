using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using Broker.Transport;

namespace Broker.McpAdapter;

/// <summary>
/// Delegate for dispatching a tool call to the Windows Server MCP Broker.
/// Enables mock testing without requiring a live Windows Named Pipe.
/// </summary>
public delegate Task<ToolExecutionResult> BrokerPipeDispatcher(
    string toolId, Dictionary<string, string> parameters, CancellationToken ct);

public sealed record ToolExecutionResult(bool Success, string? RejectReason, string? Payload);

/// <summary>
/// Implements the standard Model Context Protocol (MCP) JSON-RPC 2.0 stdio server.
/// Translates standard MCP client requests into broker named pipe protocol operations.
/// </summary>
public sealed class McpServer
{
    private readonly string _manifestPath;
    private readonly BrokerPipeDispatcher _dispatcher;
    private readonly string _pipeName;

    public McpServer(string manifestPath, string pipeName = "McpBroker", BrokerPipeDispatcher? dispatcher = null)
    {
        _manifestPath = manifestPath;
        _pipeName = pipeName;
        _dispatcher = dispatcher ?? (async (toolId, parameters, ct) => await CallBrokerViaPipeAsync(pipeName, toolId, parameters, ct));
    }

    /// <summary>
    /// Processes incoming JSON-RPC 2.0 messages from stdio.
    /// Supports both line-delimited and header-delimited (Content-Length) JSON-RPC framing.
    /// </summary>
    public async Task RunAsync(TextReader reader, TextWriter writer, CancellationToken ct = default)
    {
        while (!ct.IsCancellationRequested)
        {
            var line = await reader.ReadLineAsync(ct);
            if (line is null) break;

            if (string.IsNullOrWhiteSpace(line)) continue;

            // Handle optional Content-Length header prefix
            if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
            {
                var lengthStr = line.Substring("Content-Length:".Length).Trim();
                if (int.TryParse(lengthStr, out var length))
                {
                    // Read empty line separator
                    await reader.ReadLineAsync(ct);
                    var buffer = new char[length];
                    int read = 0;
                    while (read < length)
                    {
                        int n = await reader.ReadAsync(buffer.AsMemory(read, length - read), ct);
                        if (n == 0) break;
                        read += n;
                    }
                    line = new string(buffer, 0, read);
                }
            }

            var responseJson = await ProcessMessageAsync(line, ct);
            if (!string.IsNullOrEmpty(responseJson))
            {
                await writer.WriteLineAsync(responseJson.AsMemory(), ct);
                await writer.FlushAsync(ct);
            }
        }
    }

    /// <summary>
    /// Processes a single JSON-RPC 2.0 request or notification and produces a JSON response string (or null for notifications).
    /// </summary>
    public async Task<string?> ProcessMessageAsync(string messageJson, CancellationToken ct = default)
    {
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(messageJson);
        }
        catch (JsonException)
        {
            return SerializeError(null, -32700, "Parse error: Invalid JSON");
        }

        using (doc)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return SerializeError(null, -32600, "Invalid Request: Expected JSON object");
            }

            // Extract id (null if notification)
            JsonElement? id = null;
            if (root.TryGetProperty("id", out var idElem))
            {
                id = idElem.Clone();
            }

            if (!root.TryGetProperty("method", out var methodElem) || methodElem.ValueKind != JsonValueKind.String)
            {
                return SerializeError(id, -32600, "Invalid Request: Missing 'method' string");
            }

            var method = methodElem.GetString() ?? string.Empty;
            root.TryGetProperty("params", out var paramsElem);

            switch (method)
            {
                case "initialize":
                    return HandleInitialize(id);

                case "notifications/initialized":
                    // MCP notifications require no response
                    return null;

                case "tools/list":
                    return HandleToolsList(id);

                case "tools/call":
                    return await HandleToolsCallAsync(id, paramsElem, ct);

                case "ping":
                    return SerializeResult(id, new { });

                default:
                    if (id.HasValue)
                    {
                        return SerializeError(id, -32601, $"Method not found: '{method}'");
                    }
                    return null;
            }
        }
    }

    private static string HandleInitialize(JsonElement? id)
    {
        var result = new
        {
            protocolVersion = "2024-11-05",
            capabilities = new
            {
                tools = new { }
            },
            serverInfo = new
            {
                name = "windows-server-mcp",
                version = "1.0.0"
            }
        };
        return SerializeResult(id, result);
    }

    private string HandleToolsList(JsonElement? id)
    {
        var tools = new List<object>();

        if (File.Exists(_manifestPath))
        {
            try
            {
                using var manifestDoc = JsonDocument.Parse(File.ReadAllText(_manifestPath));
                if (manifestDoc.RootElement.TryGetProperty("tools", out var toolsArray) &&
                    toolsArray.ValueKind == JsonValueKind.Array)
                {
                    foreach (var toolElem in toolsArray.EnumerateArray())
                    {
                        // Exclude revoked tools
                        if (toolElem.TryGetProperty("revoked", out var revoked) && revoked.GetBoolean())
                            continue;

                        var toolId = toolElem.GetProperty("toolId").GetString() ?? "";
                        var desc = toolElem.TryGetProperty("description", out var d) ? d.GetString() ?? "" : "";

                        // Build parameters input schema compliant with JSON Schema draft-07
                        var properties = new Dictionary<string, object>();
                        var requiredList = new List<string>();

                        if (toolElem.TryGetProperty("parameters", out var paramsObj) &&
                            paramsObj.ValueKind == JsonValueKind.Object)
                        {
                            foreach (var p in paramsObj.EnumerateObject())
                            {
                                var pName = p.Name;
                                var pType = "string";
                                var pDesc = "";
                                if (p.Value.TryGetProperty("type", out var t)) pType = t.GetString() ?? "string";
                                if (p.Value.TryGetProperty("description", out var pd)) pDesc = pd.GetString() ?? "";
                                var isReq = p.Value.TryGetProperty("required", out var req) && req.GetBoolean();

                                properties[pName] = new
                                {
                                    type = pType,
                                    description = pDesc
                                };

                                if (isReq) requiredList.Add(pName);
                            }
                        }

                        tools.Add(new
                        {
                            name = toolId,
                            description = desc,
                            inputSchema = new
                            {
                                type = "object",
                                properties = properties,
                                required = requiredList
                            }
                        });
                    }
                }
            }
            catch
            {
                // Fallback to empty tools on manifest read error
            }
        }

        return SerializeResult(id, new { tools });
    }

    private async Task<string> HandleToolsCallAsync(JsonElement? id, JsonElement paramsElem, CancellationToken ct)
    {
        if (paramsElem.ValueKind != JsonValueKind.Object)
        {
            return SerializeError(id, -32602, "Invalid params: Expected object");
        }

        if (!paramsElem.TryGetProperty("name", out var nameElem) || nameElem.ValueKind != JsonValueKind.String)
        {
            return SerializeError(id, -32602, "Invalid params: Missing tool 'name'");
        }

        var toolId = nameElem.GetString() ?? string.Empty;
        var parameters = new Dictionary<string, string>();

        if (paramsElem.TryGetProperty("arguments", out var argsElem) && argsElem.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in argsElem.EnumerateObject())
            {
                parameters[prop.Name] = prop.Value.ValueKind == JsonValueKind.String
                    ? prop.Value.GetString() ?? string.Empty
                    : prop.Value.GetRawText();
            }
        }

        try
        {
            var result = await _dispatcher(toolId, parameters, ct);
            if (result.Success)
            {
                return SerializeResult(id, new
                {
                    content = new[]
                    {
                        new { type = "text", text = result.Payload ?? "{}" }
                    },
                    isError = false
                });
            }
            else
            {
                var errorText = $"Tool call rejected: {result.RejectReason}";
                if (!string.IsNullOrWhiteSpace(result.Payload))
                {
                    errorText += $"\nDetails: {result.Payload}";
                }

                return SerializeResult(id, new
                {
                    content = new[]
                    {
                        new { type = "text", text = errorText }
                    },
                    isError = true
                });
            }
        }
        catch (Exception ex)
        {
            return SerializeResult(id, new
            {
                content = new[]
                {
                    new { type = "text", text = $"Execution error: {ex.Message}" }
                },
                isError = true
            });
        }
    }

    private static async Task<ToolExecutionResult> CallBrokerViaPipeAsync(
        string pipeName, string toolId, Dictionary<string, string> parameters, CancellationToken ct)
    {
        using var clientStream = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await clientStream.ConnectAsync(5000, ct);

        var requestJson = JsonSerializer.Serialize(new
        {
            type = "tools/call",
            toolId = toolId,
            correlationId = Guid.NewGuid().ToString("N"),
            parameters = parameters
        });

        await McpFraming.WriteFrameAsync(clientStream, requestJson, ct);

        var responseJson = await McpFraming.ReadFrameAsync(clientStream, TimeSpan.FromSeconds(30), ct);
        if (responseJson is null)
        {
            return new ToolExecutionResult(false, "pipe-closed-without-response", null);
        }

        using var doc = JsonDocument.Parse(responseJson);
        var root = doc.RootElement;
        var success = root.TryGetProperty("success", out var s) && s.GetBoolean();
        var rejectReason = root.TryGetProperty("rejectReason", out var r) ? r.GetString() : null;
        var payload = root.TryGetProperty("payload", out var p) ? p.GetString() : null;

        return new ToolExecutionResult(success, rejectReason, payload);
    }

    private static string SerializeResult(JsonElement? id, object result)
    {
        return JsonSerializer.Serialize(new
        {
            jsonrpc = "2.0",
            id = id.HasValue ? (object)id.Value : null,
            result = result
        });
    }

    private static string SerializeError(JsonElement? id, int code, string message, object? data = null)
    {
        return JsonSerializer.Serialize(new
        {
            jsonrpc = "2.0",
            id = id.HasValue ? (object)id.Value : null,
            error = new
            {
                code = code,
                message = message,
                data = data
            }
        });
    }
}

