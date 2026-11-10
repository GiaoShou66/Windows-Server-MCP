using Broker.Audit;
using Broker.Host;
using Broker.JeaExecution;
using Broker.Policy;
using Broker.Registry;
using Broker.Transport;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

// CLI mode: `Broker.Host generate-jea [manifestPath] [outDir]` renders .psrc/.pssc from the
// manifest and exits, without starting the pipe listener. This is the operator's step
// between editing policy/manifest.json and running deploy/register-jea.ps1.
if (args.Length > 0 && string.Equals(args[0], "generate-jea", StringComparison.OrdinalIgnoreCase))
{
    var manifestPath = args.Length > 1 ? args[1] : "policy/manifest.json";
    var outDir = args.Length > 2 ? args[2] : "jea/generated";

    using var loggerFactory = LoggerFactory.Create(b => b.AddSimpleConsole(o => o.SingleLine = true));
    var manifestLogger = loggerFactory.CreateLogger<Broker.Registry.ManifestStore>();

    var integrityPath = manifestPath + ".sha256";
    using var store = new Broker.Registry.ManifestStore(
        manifestPath, manifestLogger, requireIntegrity: true, integrityPath: integrityPath);
    var activeTools = store.All.Where(t => !t.Revoked).ToList();

    if (activeTools.Count == 0)
    {
        Console.Error.WriteLine($"No active tools found in {manifestPath}; nothing to generate.");
        return 1;
    }

    var generator = new Broker.JeaExecution.JeaConfigGenerator(outDir);
    try
    {
        var written = generator.GenerateAll(activeTools);
        Console.WriteLine($"Generated {written.Count} file(s) into {outDir}:");
        foreach (var f in written) Console.WriteLine($"  {f}");
        return 0;
    }
    catch (InvalidOperationException ex)
    {
        // config error in the manifest (missing accessGroup / moduleName / endpoint conflict)
        Console.Error.WriteLine($"Generation refused: {ex.Message}");
        return 1;
    }
}

// CLI mode: `Broker.Host self-check [appsettingsPath]`
// Allows an AI agent or automated orchestrator to verify that the broker's configuration
// is complete, valid, and free of placeholder credentials before starting.
if (args.Length > 0 && string.Equals(args[0], "self-check", StringComparison.OrdinalIgnoreCase))
{
    var configBuilder = new ConfigurationBuilder();
    var appsettingsPath = args.Length > 1 ? args[1] : "src/Broker.Host/appsettings.json";
    if (File.Exists(appsettingsPath))
    {
        configBuilder.AddJsonFile(Path.GetFullPath(appsettingsPath), optional: false);
    }
    else
    {
        configBuilder.AddJsonFile("appsettings.json", optional: true);
    }
    var config = configBuilder.Build();

    using var loggerFactory = LoggerFactory.Create(b => b.AddConsole(o =>
    {
        o.LogToStandardErrorThreshold = LogLevel.Trace;
    }));
    var logger = loggerFactory.CreateLogger("Broker.Host.SelfCheck");

    var manifestPath = config["Manifest:Path"] ?? "policy/manifest.json";
    var integrityPath = config["Manifest:IntegrityPath"] ?? (manifestPath + ".sha256");
    var requireIntegrity = !bool.TryParse(config["Manifest:RequireIntegrity"], out var reqInt) || reqInt;

    try
    {
        using var store = new Broker.Registry.ManifestStore(
            manifestPath, loggerFactory.CreateLogger<Broker.Registry.ManifestStore>(), requireIntegrity, integrityPath);

        bool placeholdersOk = Worker.CheckConfigurationPlaceholders(config, store.All, logger);
        var activeTools = store.All.Where(t => !t.Revoked).ToList();
        var revokedTools = store.All.Where(t => t.Revoked).ToList();

        bool dirsOk = true;
        var transcriptDir = config["Jea:TranscriptDir"] ?? @"C:\McpBroker\Transcripts";
        try
        {
            Broker.Core.DirectoryProtection.VerifyProtected(transcriptDir);
        }
        catch (Exception ex)
        {
            logger.LogError("Transcript directory verification failed: {Msg}", ex.Message);
            dirsOk = false;
        }

        var corrLog = config["Audit:CorrelationLogPath"] ?? @"C:\McpBroker\correlation.log";
        var corrDir = Path.GetDirectoryName(Path.GetFullPath(corrLog));
        if (!string.IsNullOrEmpty(corrDir))
        {
            try
            {
                Broker.Core.DirectoryProtection.VerifyProtected(corrDir);
            }
            catch (Exception ex)
            {
                logger.LogError("Correlation log directory verification failed: {Msg}", ex.Message);
                dirsOk = false;
            }
        }

        var verifier = new Broker.Registry.SignatureVerifier(loggerFactory.CreateLogger<Broker.Registry.SignatureVerifier>());
        bool signaturesOk = true;
        foreach (var tool in activeTools)
        {
            if (!verifier.Verify(tool))
            {
                logger.LogError("Self-check: signature invalid or untrusted for tool {Tool}", tool.ToolId);
                signaturesOk = false;
            }
        }

        bool allOk = placeholdersOk && dirsOk && signaturesOk;

        if (allOk)
        {
            Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new
            {
                status = "passed",
                manifestPath,
                totalTools = store.All.Count,
                activeTools = activeTools.Count,
                revokedTools = revokedTools.Count,
                message = "Broker configuration self-check passed. Valid signatures, verified ACLs, and zero placeholder credentials."
            }, new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
            return 0;
        }
        else
        {
            Console.Error.WriteLine(System.Text.Json.JsonSerializer.Serialize(new
            {
                status = "failed",
                manifestPath,
                totalTools = store.All.Count,
                activeTools = activeTools.Count,
                revokedTools = revokedTools.Count,
                message = "Broker configuration self-check failed due to unconfigured placeholders, invalid signatures, or broad ACLs. See logs."
            }, new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
            return 1;
        }
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Self-check failed to load manifest: {ex.Message}");
        return 1;
    }
}

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddWindowsService(opts => opts.ServiceName = "McpBroker");

// Registry
builder.Services.AddSingleton(sp =>
{
    var cfg = sp.GetRequiredService<Microsoft.Extensions.Configuration.IConfiguration>();
    var path = cfg["Manifest:Path"] ?? "policy/manifest.json";
    bool requireIntegrity = !bool.TryParse(cfg["Manifest:RequireIntegrity"], out var configured) || configured;
    return new ManifestStore(path, sp.GetRequiredService<ILogger<ManifestStore>>(), requireIntegrity, cfg["Manifest:IntegrityPath"]);
});
builder.Services.AddSingleton<SignatureVerifier>();
builder.Services.AddSingleton<ISignatureVerifier>(sp => sp.GetRequiredService<SignatureVerifier>());

// Policy
builder.Services.AddSingleton<ParameterValidator>();
builder.Services.AddSingleton<UntrustedSourceGate>();
builder.Services.AddSingleton<ArgvBuilder>();
builder.Services.AddSingleton<AmsiScanner>();
builder.Services.AddSingleton(sp =>
{
    var cfg = sp.GetRequiredService<Microsoft.Extensions.Configuration.IConfiguration>();
    bool requireDistinct = bool.TryParse(cfg["Elicitation:RequireDistinctApprover"], out var r) && r;
    var approvers = cfg.GetSection("Elicitation:ApproverSids").Get<string[]>() ?? Array.Empty<string>();
    return new ConsentEngine(requireDistinct, approvers);
});
builder.Services.AddSingleton(sp =>
{
    var cfg = sp.GetRequiredService<Microsoft.Extensions.Configuration.IConfiguration>();
    int window = int.TryParse(cfg["Taint:WindowSeconds"], out var w) ? w : 300;
    return new TaintTracker(window);
});
builder.Services.AddSingleton(sp =>
{
    var cfg = sp.GetRequiredService<Microsoft.Extensions.Configuration.IConfiguration>();
    var path = cfg["Audit:CorrelationLogPath"] ?? @"C:\McpBroker\correlation.log";
    return new CorrelationLog(path);
});
builder.Services.AddSingleton(sp =>
{
    var cfg = sp.GetRequiredService<Microsoft.Extensions.Configuration.IConfiguration>();
    int perMin = int.TryParse(cfg["RateLimit:CallsPerMinute"], out var a) ? a : 60;
    int destPerHour = int.TryParse(cfg["RateLimit:DestructivePerHour"], out var b) ? b : 10;
    return new RateLimiter(perMin, destPerHour);
});

// JEA
builder.Services.AddSingleton<JeaEndpointClient>();

// Audit
builder.Services.AddSingleton(sp =>
{
    var cfg = sp.GetRequiredService<Microsoft.Extensions.Configuration.IConfiguration>();
    var dir = cfg["Jea:TranscriptDir"] ?? @"C:\McpBroker\Transcripts";
    return new TranscriptAggregator(dir, sp.GetRequiredService<ILogger<TranscriptAggregator>>());
});

// Pipeline + transport
builder.Services.AddSingleton<IToolCallDispatcher, BrokerPipeline>();
builder.Services.AddSingleton<PipeSecurityFactory>();
builder.Services.AddSingleton<ElicitationRouter>();
builder.Services.AddSingleton(sp =>
{
    var lifetime = sp.GetRequiredService<IHostApplicationLifetime>();
    return new NamedPipeServer(
        sp.GetRequiredService<PipeSecurityFactory>(),
        sp.GetRequiredService<IToolCallDispatcher>(),
        sp.GetRequiredService<ElicitationRouter>(),
        sp.GetRequiredService<Microsoft.Extensions.Configuration.IConfiguration>(),
        sp.GetRequiredService<ILogger<NamedPipeServer>>(),
        () => lifetime.StopApplication());
});
builder.Services.AddSingleton<ApprovalPipeServer>();
builder.Services.AddHostedService<Worker>();

var host = builder.Build();
host.Run();
return 0;
