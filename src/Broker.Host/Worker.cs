using Broker.Core;
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
        bool placeholdersOk = RunPlaceholderSelfCheck();
        bool startupOk = RunStartupSelfCheck();
        if (!placeholdersOk || !startupOk)
        {
            _logger.LogCritical("Startup self-check failed; refusing to open pipe listener");
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

    /// <summary>
    /// Self-check for unconfigured deployment placeholders.
    /// Fails closed: if any placeholder thumbprint, placeholder SID, or misconfigured distinct
    /// approver list is detected, logs a single clear, actionable error and refuses to start.
    /// </summary>
    internal bool RunPlaceholderSelfCheck() =>
        CheckConfigurationPlaceholders(_config, _manifest.All, _logger);

    /// <summary>
    /// Pure validation logic for unconfigured deployment placeholders so it can be tested
    /// directly without spinning up background services.
    /// </summary>
    internal static bool CheckConfigurationPlaceholders(
        IConfiguration config,
        IEnumerable<ToolManifest> tools,
        ILogger logger)
    {
        bool ok = true;

        var allowedSids = config.GetSection("Pipe:AllowedSids").Get<string[]>() ?? Array.Empty<string>();
        foreach (var sid in allowedSids)
        {
            if (PlaceholderDiagnostics.IsPlaceholderSid(sid))
            {
                logger.LogError("Unconfigured deployment placeholder: Pipe:AllowedSids contains '{Sid}'. Replace with genuine authorized caller SIDs in appsettings.json before starting the broker.", sid);
                ok = false;
            }
        }

        bool requireDistinct = bool.TryParse(config["Elicitation:RequireDistinctApprover"], out var distinct) && distinct;
        var approverSids = config.GetSection("Elicitation:ApproverSids").Get<string[]>() ?? Array.Empty<string>();
        if (requireDistinct && (approverSids.Length == 0 || approverSids.All(string.IsNullOrWhiteSpace)))
        {
            logger.LogError("Unconfigured deployment placeholder: Elicitation:RequireDistinctApprover is true, but Elicitation:ApproverSids is empty. Configure authorized approver SIDs in appsettings.json before starting the broker.");
            ok = false;
        }

        // Invariant 1: Caller SIDs and approver SIDs are disjoint. The broker refuses to start otherwise.
        var overlappingSids = allowedSids
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Intersect(approverSids.Where(s => !string.IsNullOrWhiteSpace(s)), StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (overlappingSids.Count > 0)
        {
            logger.LogError("Invariant 1 violation: Caller SIDs and approver SIDs must be disjoint. The broker refuses to start otherwise. Overlapping SIDs: {Overlaps}", string.Join(", ", overlappingSids));
            ok = false;
        }

        foreach (var tool in tools)
        {
            if (tool.Revoked) continue;

            if (PlaceholderDiagnostics.IsPlaceholderThumbprint(tool.Server.SignatureThumbprint))
            {
                logger.LogError("Unconfigured deployment placeholder: Tool '{Tool}' has placeholder thumbprint '{Thumbprint}'. Sign the tool script and record its genuine Authenticode thumbprint in policy/manifest.json before starting the broker.", tool.ToolId, tool.Server.SignatureThumbprint);
                ok = false;
            }
        }

        return ok;
    }

    private bool RunStartupSelfCheck()
    {
        bool ok = true;

        // Transcripts must not be writable by every local user. Creating the directory with
        // default inheritance under C:\ would hand BUILTIN\Users (M) the transcript store.
        var transcriptDir = _config["Jea:TranscriptDir"] ?? @"C:\McpBroker\Transcripts";
        try
        {
            DirectoryProtection.VerifyProtected(transcriptDir);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Transcript directory not provisionable: {Dir}", transcriptDir);
            ok = false;
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
