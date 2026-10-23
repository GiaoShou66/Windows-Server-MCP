using Broker.Registry;
using Broker.Transport;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Broker.Host;

/// <summary>
/// Owns the pipe listener lifecycle. Runs a fail-closed startup self-check before
/// opening the pipe: any failure logs critical and refuses to start (no silent degrade).
/// </summary>
public sealed class Worker : BackgroundService
{
    private readonly NamedPipeServer _pipeServer;
    private readonly ApprovalPipeServer _approvalServer;
    private readonly ManifestStore _manifest;
    private readonly SignatureVerifier _signatures;
    private readonly IConfiguration _config;
    private readonly ILogger<Worker> _logger;
    private readonly IHostApplicationLifetime _lifetime;

    public Worker(
        NamedPipeServer pipeServer, ApprovalPipeServer approvalServer, ManifestStore manifest,
        SignatureVerifier signatures, IConfiguration config, ILogger<Worker> logger,
        IHostApplicationLifetime lifetime)
    {
        _pipeServer = pipeServer;
        _approvalServer = approvalServer;
        _manifest = manifest;
        _signatures = signatures;
        _config = config;
        _logger = logger;
        _lifetime = lifetime;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!RunStartupSelfCheck())
        {
            _logger.LogCritical("Startup self-check failed; refusing to open pipe listener");
            // Non-zero so a service manager sees a failed start (recovery actions, alerting),
            // not a clean stop.
            Environment.ExitCode = 1;
            _lifetime.StopApplication();
            return;
        }

        _logger.LogInformation("MCP broker self-check passed; starting pipe listener");

        var servers = new List<Task> { _pipeServer.RunAsync(stoppingToken) };

        if (bool.TryParse(_config["Elicitation:RequireDistinctApprover"], out var distinct) && distinct)
        {
            _logger.LogInformation("Distinct-approver mode on; starting approval pipe listener");
            servers.Add(_approvalServer.RunAsync(stoppingToken));
        }

        await Task.WhenAll(servers);
    }

    private bool RunStartupSelfCheck()
    {
        bool ok = true;

        var transcriptDir = _config["Jea:TranscriptDir"] ?? @"C:\McpBroker\Transcripts";
        if (!Directory.Exists(transcriptDir))
        {
            try { Directory.CreateDirectory(transcriptDir); }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Transcript directory not writable: {Dir}", transcriptDir);
                ok = false;
            }
        }

        foreach (var tool in _manifest.All)
        {
            if (tool.Revoked) continue;

            if (!_signatures.Verify(tool))
            {
                _logger.LogError("Self-check: signature invalid for tool {Tool}", tool.ToolId);
                ok = false;
            }

            if (string.IsNullOrWhiteSpace(tool.JeaMapping.EndpointName))
            {
                _logger.LogError("Self-check: tool {Tool} has no JEA endpoint mapping", tool.ToolId);
                ok = false;
            }
        }

        return ok;
    }
}
