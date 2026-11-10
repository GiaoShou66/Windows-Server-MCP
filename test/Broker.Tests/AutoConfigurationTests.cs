using System.Diagnostics;
using System.Text.Json;
using Broker.Registry;
using Xunit;

namespace Broker.Tests;

/// <summary>
/// H5: Verifies end-to-end auto-configuration without mutating the repository checkout or system trust.
/// All tests execute against an isolated temporary directory workspace and clean up on completion.
/// </summary>
public class AutoConfigurationTests : IDisposable
{
    private readonly string _workspaceDir;
    private readonly string _repoRoot;

    public AutoConfigurationTests()
    {
        _repoRoot = GetRepoRoot();
        _workspaceDir = Path.Combine(Path.GetTempPath(), $"mcp-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_workspaceDir);
        CopyDirectory(Path.Combine(_repoRoot, "deploy"), Path.Combine(_workspaceDir, "deploy"));
        CopyDirectory(Path.Combine(_repoRoot, "policy"), Path.Combine(_workspaceDir, "policy"));
        CopyDirectory(Path.Combine(_repoRoot, "jea"), Path.Combine(_workspaceDir, "jea"));

        var hostTargetDir = Path.Combine(_workspaceDir, "src", "Broker.Host");
        Directory.CreateDirectory(hostTargetDir);
        File.Copy(Path.Combine(_repoRoot, "src", "Broker.Host", "appsettings.json"), Path.Combine(hostTargetDir, "appsettings.json"), overwrite: true);

        // Copy compiled Host binaries if available to support generate-jea execution in isolated workspace
        var binSource = Path.Combine(_repoRoot, "src", "Broker.Host", "bin");
        if (Directory.Exists(binSource))
        {
            CopyDirectory(binSource, Path.Combine(hostTargetDir, "bin"));
        }
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_workspaceDir))
            {
                Directory.Delete(_workspaceDir, recursive: true);
            }
        }
        catch
        {
            // Best effort cleanup of temp files
        }
    }

    private static string GetRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "mcp-broker.sln")))
        {
            dir = dir.Parent;
        }
        return dir?.FullName ?? throw new InvalidOperationException("Could not locate repo root containing mcp-broker.sln");
    }

    private static void CopyDirectory(string sourceDir, string targetDir)
    {
        Directory.CreateDirectory(targetDir);
        foreach (var file in Directory.GetFiles(sourceDir))
        {
            File.Copy(file, Path.Combine(targetDir, Path.GetFileName(file)), overwrite: true);
        }
        foreach (var dir in Directory.GetDirectories(sourceDir))
        {
            CopyDirectory(dir, Path.Combine(targetDir, Path.GetFileName(dir)));
        }
    }

    private (int exitCode, string stdout, string stderr) RunScript(params string[] arguments)
    {
        var scriptPath = Path.Combine(_workspaceDir, "deploy", "auto-configure.ps1");
        var psi = new ProcessStartInfo("powershell.exe")
        {
            ArgumentList =
            {
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy", "Bypass",
                "-File", scriptPath,
                "-RepoRoot", _workspaceDir
            },
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            WorkingDirectory = _workspaceDir
        };
        psi.EnvironmentVariables["PSModulePath"] = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "Modules");

        foreach (var arg in arguments)
        {
            psi.ArgumentList.Add(arg);
        }

        using var proc = new Process { StartInfo = psi };
        var stdoutBuilder = new System.Text.StringBuilder();
        var stderrBuilder = new System.Text.StringBuilder();

        proc.OutputDataReceived += (_, e) => { if (e.Data != null) stdoutBuilder.AppendLine(e.Data); };
        proc.ErrorDataReceived += (_, e) => { if (e.Data != null) stderrBuilder.AppendLine(e.Data); };

        proc.Start();
        proc.BeginOutputReadLine();
        proc.BeginErrorReadLine();
        if (!proc.WaitForExit(90_000))
        {
            try { proc.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException($"PowerShell script timed out after 90s. Stdout: {stdoutBuilder}, Stderr: {stderrBuilder}");
        }

        return (proc.ExitCode, stdoutBuilder.ToString().Trim(), stderrBuilder.ToString().Trim());
    }

    [Fact]
    public void AutoConfigureDiscoverOutputsValidJsonWithExpectedStructure()
    {
        var (exitCode, stdout, stderr) = RunScript("-Discover");

        Assert.True(exitCode == 0, $"Script failed with exitCode {exitCode}. Stderr: {stderr}");
        Assert.False(string.IsNullOrWhiteSpace(stdout), "Stdout was empty");

        using var doc = JsonDocument.Parse(stdout);
        var root = doc.RootElement;

        Assert.True(root.TryGetProperty("Machine", out var machine));
        Assert.True(machine.TryGetProperty("Name", out _));
        Assert.True(machine.TryGetProperty("IsDomainJoined", out _));

        Assert.True(root.TryGetProperty("Identity", out var identity));
        Assert.True(identity.TryGetProperty("CurrentSid", out var sid));
        Assert.StartsWith("S-1-5-", sid.GetString());

        Assert.True(root.TryGetProperty("Features", out var features));
        Assert.True(features.TryGetProperty("ActiveDirectory", out _));
        Assert.True(features.TryGetProperty("HyperV", out _));

        Assert.True(root.TryGetProperty("Manifest", out var manifest));
        Assert.True(manifest.TryGetProperty("TotalTools", out var totalTools));
        Assert.Equal(62, totalTools.GetInt32());

        Assert.True(root.TryGetProperty("AppSettings", out var appSettings));
        Assert.True(appSettings.TryGetProperty("AllowedSids", out _));
    }

    [Fact]
    public void AutoConfigurePlanGeneratesTailoredDevProfileWithDisjointSidsAndSafeAccessGroup()
    {
        var tempProfile = Path.Combine(_workspaceDir, "test-profile.json");
        var (exitCode, stdout, stderr) = RunScript("-Plan", "-DevMode", "-ProfilePath", tempProfile);

        Assert.True(exitCode == 0, $"Script failed with exitCode {exitCode}. Stderr: {stderr}");
        Assert.True(File.Exists(tempProfile), "Plan profile file was not created");

        using var doc = JsonDocument.Parse(File.ReadAllText(tempProfile));
        var root = doc.RootElement;

        Assert.Equal("Development", root.GetProperty("mode").GetString());
        Assert.False(root.GetProperty("identity").GetProperty("requireDistinctApprover").GetBoolean());

        // C2 & Invariant 3: Must NOT be BUILTIN\Users
        var accessGroup = root.GetProperty("identity").GetProperty("accessGroup").GetString();
        Assert.NotEqual("BUILTIN\\Users", accessGroup);
        Assert.Equal("McpBrokerServiceGroup", accessGroup);

        // Invariant 1: Caller SIDs and Approver SIDs must be disjoint
        var callers = root.GetProperty("identity").GetProperty("callerSids");
        var approvers = root.GetProperty("identity").GetProperty("approverSids");
        Assert.True(callers.GetArrayLength() > 0);
        Assert.True(approvers.GetArrayLength() > 0);

        var callerSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var c in callers.EnumerateArray())
        {
            callerSet.Add(c.GetString()!);
        }

        foreach (var a in approvers.EnumerateArray())
        {
            Assert.DoesNotContain(a.GetString()!, callerSet);
        }
    }

    [Fact]
    public void AutoConfigurePlanProductionModeWithoutCertThumbprintThrows()
    {
        // C1: Production mode requires explicit enterprise CA cert thumbprint; implicit DevMode is rejected
        var (exitCode, stdout, stderr) = RunScript("-Plan");

        Assert.NotEqual(0, exitCode);
        Assert.Contains("Production mode requires an explicit enterprise CA Code Signing certificate thumbprint", stdout + stderr);
    }

    [Fact]
    public void AutoConfigurePlanOverlappingCallerAndApproverSidsFailsClosed()
    {
        // Invariant 1: Overlapping SIDs must be rejected
        const string sharedSid = "S-1-5-21-111111111-222222222-333333333-1001";
        var (exitCode, stdout, stderr) = RunScript("-Plan", "-DevMode", "-CallerSids", sharedSid, "-ApproverSids", sharedSid);

        Assert.NotEqual(0, exitCode);
        Assert.Contains("Invariant 1 violation", stdout + stderr);
    }

    [Fact]
    public void AutoConfigureFullInIsolatedDirectoryDoesNotMutateRepository()
    {
        // Snapshot real repository manifest and appsettings timestamps / contents
        var realManifestPath = Path.Combine(_repoRoot, "policy", "manifest.json");
        var realManifestHashBefore = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(realManifestPath)));

        var realAppSettingsPath = Path.Combine(_repoRoot, "src", "Broker.Host", "appsettings.json");
        var realAppSettingsHashBefore = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(realAppSettingsPath)));

        // Run full auto-configure in isolated directory
        var (exitCode, stdout, stderr) = RunScript("-Full", "-DevMode", "-SkipTests", "-SkipBuild");

        Assert.True(exitCode == 0, $"Full auto-configure failed with exitCode {exitCode}. Output: {stdout}\nStderr: {stderr}");

        using var doc = JsonDocument.Parse(stdout);
        var root = doc.RootElement;
        // H3: Since tests were skipped (-SkipTests), status is ActionRequired (never falsely reports Healthy)
        Assert.Equal("ActionRequired", root.GetProperty("Status").GetString());
        Assert.Equal("Skipped", root.GetProperty("Validation").GetProperty("UnitTestsPassed").GetString());

        // Prove that the real repo files were completely untouched
        var realManifestHashAfter = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(realManifestPath)));
        var realAppSettingsHashAfter = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(realAppSettingsPath)));

        Assert.Equal(realManifestHashBefore, realManifestHashAfter);
        Assert.Equal(realAppSettingsHashBefore, realAppSettingsHashAfter);
    }
}
