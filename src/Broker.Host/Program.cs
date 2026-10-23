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

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddWindowsService(opts => opts.ServiceName = "McpBroker");

// Registry
builder.Services.AddSingleton(sp =>
{
    var cfg = sp.GetRequiredService<Microsoft.Extensions.Configuration.IConfiguration>();
    var path = cfg["Manifest:Path"] ?? "policy/manifest.json";
    bool requireIntegrity = ConfigReader.Bool(cfg, "Manifest:RequireIntegrity", true);
    return new ManifestStore(path, sp.GetRequiredService<ILogger<ManifestStore>>(), requireIntegrity, cfg["Manifest:IntegrityPath"]);
});
builder.Services.AddSingleton<SignatureVerifier>();
builder.Services.AddSingleton<ISignatureVerifier>(sp => sp.GetRequiredService<SignatureVerifier>());

// Policy
builder.Services.AddSingleton<ParameterValidator>();
builder.Services.AddSingleton<UntrustedSourceGate>();
builder.Services.AddSingleton<ArgvBuilder>();
builder.Services.AddSingleton(sp =>
{
    var cfg = sp.GetRequiredService<Microsoft.Extensions.Configuration.IConfiguration>();
    // Absent key keeps the documented default; a present-but-unrecognized value stops startup.
    var mode = cfg["Amsi:Mode"] is { } raw ? AmsiOptions.ParseMode(raw) : AmsiMode.BestEffort;
    return new AmsiScanner(sp.GetRequiredService<ILogger<AmsiScanner>>(), mode);
});
builder.Services.AddSingleton(sp =>
{
    var cfg = sp.GetRequiredService<Microsoft.Extensions.Configuration.IConfiguration>();
    bool requireDistinct = ConfigReader.Bool(cfg, "Elicitation:RequireDistinctApprover", false);
    var approvers = cfg.GetSection("Elicitation:ApproverSids").Get<string[]>() ?? Array.Empty<string>();
    return new ConsentEngine(requireDistinct, approvers);
});
builder.Services.AddSingleton(sp =>
{
    var cfg = sp.GetRequiredService<Microsoft.Extensions.Configuration.IConfiguration>();
    int window = ConfigReader.Int(cfg, "Taint:WindowSeconds", 300);
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
    return new RateLimiter(
        ConfigReader.Int(cfg, "RateLimit:CallsPerMinute", 60),
        ConfigReader.Int(cfg, "RateLimit:DestructivePerHour", 10, 0),
        ConfigReader.Int(cfg, "RateLimit:GlobalCallsPerMinute", 600, 0));
});

// JEA: the pipeline only ever sees IJeaExecutor, bounded by global/endpoint/tool limits.
builder.Services.AddSingleton(sp =>
{
    var cfg = sp.GetRequiredService<Microsoft.Extensions.Configuration.IConfiguration>();
    var defaults = new JeaClientOptions();
    return new JeaEndpointClient(
        sp.GetRequiredService<ILogger<JeaEndpointClient>>(),
        new JeaClientOptions(
            ConfigReader.Int(cfg, "Jea:OpenTimeoutMs", defaults.OpenTimeoutMs),
            ConfigReader.Int(cfg, "Jea:OperationTimeoutMs", defaults.OperationTimeoutMs)));
});
builder.Services.AddSingleton<IJeaExecutor>(sp =>
{
    var cfg = sp.GetRequiredService<Microsoft.Extensions.Configuration.IConfiguration>();
    var d = new JeaExecutionLimits();
    var limits = new JeaExecutionLimits
    {
        MaxConcurrentTotal = ConfigReader.Int(cfg, "Jea:Limits:MaxConcurrentTotal", d.MaxConcurrentTotal, 1),
        MaxConcurrentPerEndpoint = ConfigReader.Int(cfg, "Jea:Limits:MaxConcurrentPerEndpoint", d.MaxConcurrentPerEndpoint, 1),
        MaxConcurrentPerTool = ConfigReader.Int(cfg, "Jea:Limits:MaxConcurrentPerTool", d.MaxConcurrentPerTool, 1),
        MaxQueueLength = ConfigReader.Int(cfg, "Jea:Limits:MaxQueueLength", d.MaxQueueLength, 0),
        QueueWaitTimeout = TimeSpan.FromSeconds(ConfigReader.Int(cfg, "Jea:Limits:QueueWaitSeconds", (int)d.QueueWaitTimeout.TotalSeconds)),
        ExecutionTimeout = TimeSpan.FromSeconds(ConfigReader.Int(cfg, "Jea:Limits:ExecutionTimeoutSeconds", (int)d.ExecutionTimeout.TotalSeconds)),
        MaxResponseBytes = ConfigReader.Int(cfg, "Jea:Limits:MaxResponseBytes", d.MaxResponseBytes, 1)
    };
    return new BoundedJeaExecutor(
        sp.GetRequiredService<JeaEndpointClient>(), limits, sp.GetRequiredService<ILogger<BoundedJeaExecutor>>());
});

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
builder.Services.AddSingleton<NamedPipeServer>();
builder.Services.AddSingleton<ApprovalPipeServer>();
builder.Services.AddHostedService<Worker>();

try
{
    var host = builder.Build();
    host.Run();
}
catch (InvalidOperationException ex) when (ex.Message.StartsWith("Configuration value", StringComparison.Ordinal))
{
    // A bad setting is an operator error: say which key and exit non-zero, without a crash dump.
    Console.Error.WriteLine($"Startup refused: {ex.Message}");
    return 1;
}

return Environment.ExitCode;
