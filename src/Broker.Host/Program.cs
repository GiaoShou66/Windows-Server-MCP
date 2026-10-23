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
    bool requireIntegrity = !bool.TryParse(cfg["Manifest:RequireIntegrity"], out var configured) || configured;
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
    return new RateLimiter(
        IntSetting(cfg, "RateLimit:CallsPerMinute", 60),
        IntSetting(cfg, "RateLimit:DestructivePerHour", 10),
        IntSetting(cfg, "RateLimit:GlobalCallsPerMinute", 600));
});

// JEA: the pipeline only ever sees IJeaExecutor, bounded by global/endpoint/tool limits.
builder.Services.AddSingleton(sp =>
{
    var cfg = sp.GetRequiredService<Microsoft.Extensions.Configuration.IConfiguration>();
    var defaults = new JeaClientOptions();
    return new JeaEndpointClient(
        sp.GetRequiredService<ILogger<JeaEndpointClient>>(),
        new JeaClientOptions(
            IntSetting(cfg, "Jea:OpenTimeoutMs", defaults.OpenTimeoutMs),
            IntSetting(cfg, "Jea:OperationTimeoutMs", defaults.OperationTimeoutMs)));
});
builder.Services.AddSingleton<IJeaExecutor>(sp =>
{
    var cfg = sp.GetRequiredService<Microsoft.Extensions.Configuration.IConfiguration>();
    var d = new JeaExecutionLimits();
    var limits = new JeaExecutionLimits
    {
        MaxConcurrentTotal = IntSetting(cfg, "Jea:Limits:MaxConcurrentTotal", d.MaxConcurrentTotal),
        MaxConcurrentPerEndpoint = IntSetting(cfg, "Jea:Limits:MaxConcurrentPerEndpoint", d.MaxConcurrentPerEndpoint),
        MaxConcurrentPerTool = IntSetting(cfg, "Jea:Limits:MaxConcurrentPerTool", d.MaxConcurrentPerTool),
        MaxQueueLength = IntSetting(cfg, "Jea:Limits:MaxQueueLength", d.MaxQueueLength),
        QueueWaitTimeout = TimeSpan.FromSeconds(IntSetting(cfg, "Jea:Limits:QueueWaitSeconds", (int)d.QueueWaitTimeout.TotalSeconds)),
        ExecutionTimeout = TimeSpan.FromSeconds(IntSetting(cfg, "Jea:Limits:ExecutionTimeoutSeconds", (int)d.ExecutionTimeout.TotalSeconds)),
        MaxResponseBytes = IntSetting(cfg, "Jea:Limits:MaxResponseBytes", d.MaxResponseBytes)
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

var host = builder.Build();
host.Run();
return Environment.ExitCode;

// Malformed numeric configuration must not silently fall back to a different bound than the
// operator wrote: an unparsable value stops startup instead of being replaced by a default.
static int IntSetting(IConfiguration cfg, string key, int fallback)
{
    var raw = cfg[key];
    if (raw is null) return fallback;
    return int.TryParse(raw, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var v)
        ? v
        : throw new InvalidOperationException($"Configuration value '{key}' is not a valid integer.");
}
