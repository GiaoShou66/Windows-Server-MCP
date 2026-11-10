namespace Broker.ApproverCli;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        string pipeName = "McpBroker.Approvals";

        for (int i = 0; i < args.Length; i++)
        {
            if ((args[i] == "--pipe" || args[i] == "-p") && i + 1 < args.Length)
            {
                pipeName = args[++i];
            }
        }

        var client = new ApproverClient(pipeName);
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        try
        {
            await client.RunAsync(Console.In, Console.Out, cts.Token);
            return 0;
        }
        catch (OperationCanceledException)
        {
            return 0;
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync($"[approver-cli] Fatal error: {ex.Message}");
            return 1;
        }
    }
}

