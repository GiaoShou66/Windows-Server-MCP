namespace Broker.McpAdapter;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        string pipeName = "McpBroker";
        string manifestPath = Path.Combine(AppContext.BaseDirectory, "policy", "manifest.json");

        for (int i = 0; i < args.Length; i++)
        {
            if ((args[i] == "--pipe" || args[i] == "-p") && i + 1 < args.Length)
            {
                pipeName = args[++i];
            }
            else if ((args[i] == "--manifest" || args[i] == "-m") && i + 1 < args.Length)
            {
                manifestPath = args[++i];
            }
        }

        // If manifest isn't next to executable, search up to repository root
        if (!File.Exists(manifestPath))
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir != null)
            {
                var candidate = Path.Combine(dir.FullName, "policy", "manifest.json");
                if (File.Exists(candidate))
                {
                    manifestPath = candidate;
                    break;
                }
                dir = dir.Parent;
            }
        }

        var server = new McpServer(manifestPath, pipeName);
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        try
        {
            await server.RunAsync(Console.In, Console.Out, cts.Token);
            return 0;
        }
        catch (OperationCanceledException)
        {
            return 0;
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync($"[mcp-adapter] Fatal error: {ex.Message}");
            return 1;
        }
    }
}

