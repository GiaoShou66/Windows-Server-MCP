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
builder.Services.AddSingleton<NamedPipeServer>();
builder.Services.AddSingleton<ApprovalPipeServer>();
builder.Services.AddHostedService<Worker>();

var host = builder.Build();
host.Run();
return 0;
