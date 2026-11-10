using System.Management.Automation;
using System.Management.Automation.Runspaces;
using Broker.Core;
using Broker.Host;
using Broker.Policy;
using Broker.Registry;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Broker.Tests;

file sealed class TestLogger<T> : ILogger<T>
{
    public List<string> Errors { get; } = new();
    public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;
    public bool IsEnabled(LogLevel logLevel) => true;
    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        if (logLevel >= LogLevel.Error)
        {
            Errors.Add(formatter(state, exception));
        }
    }

    private sealed class NullScope : IDisposable
    {
        public static readonly NullScope Instance = new();
        public void Dispose() { }
    }
}

/// <summary>
/// Unit tests for FIX-2: MaskFields fail-closed behavior on malformed or non-JSON payloads.
/// </summary>
public class MaskFieldsTests
{
    [Fact]
    public void ValidJsonMasksConfiguredFieldsRecursivelyAndCaseInsensitively()
    {
        var json = """
        {
            "userName": "alice",
            "objectSid": "S-1-5-21-12345-500",
            "DISTINGUISHEDNAME": "CN=Alice,DC=corp",
            "nested": {
                "Objectsid": "S-1-5-21-99999",
                "other": 42
            },
            "items": [
                { "sid": "S-1-5-32-544", "name": "Admin" },
                { "sid": "S-1-5-32-545", "name": "Users" }
            ]
        }
        """;

        var masked = BrokerPipeline.MaskFields(json, new[] { "objectSid", "distinguishedName", "sid" });

        Assert.DoesNotContain("S-1-5-21-12345-500", masked);
        Assert.DoesNotContain("CN=Alice,DC=corp", masked);
        Assert.DoesNotContain("S-1-5-21-99999", masked);
        Assert.DoesNotContain("S-1-5-32-544", masked);
        Assert.Contains("***MASKED***", masked);
        Assert.Contains("alice", masked);
        Assert.Contains("Admin", masked);
    }

    [Fact]
    public void MalformedPayloadWithMaskedFieldsFailsClosedAndNeverReturnsSensitiveValues()
    {
        var sensitiveSid = "S-1-5-21-99999999-500";
        var sensitiveDn = "CN=Administrator,CN=Users,DC=corp";
        var malformed = $"This is NOT valid JSON! objectSid: {sensitiveSid}, distinguishedName: {sensitiveDn} {{{{ trailing junk";

        var masked = BrokerPipeline.MaskFields(malformed, new[] { "objectSid", "distinguishedName" });

        // Sensitive values must NEVER be returned from an un-maskable payload.
        Assert.DoesNotContain(sensitiveSid, masked);
        Assert.DoesNotContain(sensitiveDn, masked);
        Assert.Contains("redaction-failure", masked);
    }

    [Fact]
    public void MalformedPayloadWithoutMaskedFieldsReturnsRawPayload()
    {
        var payload = "Plain text { not json }";
        var result = BrokerPipeline.MaskFields(payload, Array.Empty<string>());
        Assert.Equal(payload, result);
    }
}

/// <summary>
/// Unit tests for ArgvBuilder and ParameterValidator behavior (FIX-6 type conversion and invariants).
/// </summary>
public class ArgvBuilderAndValidatorTests
{
    [Fact]
    public void ArgvBuilderConvertsTypesCorrectlyForValidInputs()
    {
        var builder = new ArgvBuilder();
        var tool = new ToolManifest
        {
            ToolId = "test-tool",
            Parameters = new List<ToolParameter>
            {
                new() { Name = "StrParam", Type = "string", Allowlist = new ParameterAllowlist { MaxLength = 100 } },
                new() { Name = "IntParam", Type = "int", Allowlist = new ParameterAllowlist { Range = new ParamRange { Min = 1, Max = 100 } } },
                new() { Name = "BoolTrue", Type = "bool", Allowlist = new ParameterAllowlist { EnumValues = new() { "true", "false" } } },
                new() { Name = "BoolFalse", Type = "bool", Allowlist = new ParameterAllowlist { EnumValues = new() { "true", "false" } } }
            }
        };

        var raw = new Dictionary<string, string>
        {
            ["StrParam"] = "hello",
            ["IntParam"] = "42",
            ["BoolTrue"] = "true",
            ["BoolFalse"] = "false"
        };

        var argv = builder.Build(tool, raw);
        Assert.Equal("hello", argv["StrParam"]);
        Assert.Equal(42, argv["IntParam"]);
        Assert.Equal(true, argv["BoolTrue"]);
        Assert.Equal(false, argv["BoolFalse"]);
    }

    [Fact]
    public void ArgvBuilderRefusesParameterWithoutAllowlist()
    {
        var builder = new ArgvBuilder();
        var tool = new ToolManifest
        {
            ToolId = "unconstrained-tool",
            Parameters = new List<ToolParameter>
            {
                new() { Name = "Dangerous", Type = "string", Allowlist = new ParameterAllowlist() }
            }
        };

        var raw = new Dictionary<string, string> { ["Dangerous"] = "payload" };
        Assert.Throws<InvalidOperationException>(() => builder.Build(tool, raw));
    }
}

/// <summary>
/// Unit tests for FIX-3: Get-BrokerListDirectory allowlist of roots.
/// </summary>
public class ListDirectoryContentsTests : IDisposable
{
    private readonly string _testDir;
    private readonly string _modulePath;

    public ListDirectoryContentsTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), $"mcp-test-listdir-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_testDir);
        _modulePath = Path.Combine(GetRepoRoot(), "jea", "modules", "Get-BrokerListDirectory.psm1");
    }

    internal static string GetRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "mcp-broker.sln")))
        {
            dir = dir.Parent;
        }
        return dir?.FullName ?? throw new InvalidOperationException("Could not locate repo root containing mcp-broker.sln");
    }

    internal static PowerShell CreateTestPowerShell()
    {
        var iss = InitialSessionState.CreateDefault();
        iss.ExecutionPolicy = Microsoft.PowerShell.ExecutionPolicy.Bypass;
        return PowerShell.Create(iss);
    }

    [Fact]
    public void AcceptedPathInsideAllowedRootSucceeds()
    {
        var subDir = Path.Combine(_testDir, "allowed_sub");
        Directory.CreateDirectory(subDir);
        File.WriteAllText(Path.Combine(subDir, "sample.txt"), "test-content");

        var oldRoots = Environment.GetEnvironmentVariable("BROKER_ALLOWED_ROOTS");
        try
        {
            Environment.SetEnvironmentVariable("BROKER_ALLOWED_ROOTS", _testDir);
            using var ps = CreateTestPowerShell();
            ps.AddScript($"Import-Module '{_modulePath.Replace("'", "''")}'; Get-BrokerListDirectory -Path '{subDir.Replace("'", "''")}'");
            var results = ps.Invoke();

            Assert.False(ps.HadErrors, string.Join("; ", ps.Streams.Error));
            Assert.NotEmpty(results);
            var first = results.First();
            Assert.Equal("sample.txt", first.Properties["Name"]?.Value?.ToString());
        }
        finally
        {
            Environment.SetEnvironmentVariable("BROKER_ALLOWED_ROOTS", oldRoots);
        }
    }

    [Fact]
    public void RejectedPathOutsideAllowedRootThrowsPolicyError()
    {
        var outsideDir = Path.Combine(Path.GetTempPath(), $"mcp-test-outside-{Guid.NewGuid():N}");
        Directory.CreateDirectory(outsideDir);
        try
        {
            var oldRoots = Environment.GetEnvironmentVariable("BROKER_ALLOWED_ROOTS");
            try
            {
                Environment.SetEnvironmentVariable("BROKER_ALLOWED_ROOTS", _testDir);
                using var ps = CreateTestPowerShell();
                ps.AddScript($"Import-Module '{_modulePath.Replace("'", "''")}'; Get-BrokerListDirectory -Path '{outsideDir.Replace("'", "''")}'");
                var ex = Assert.Throws<RuntimeException>(() => ps.Invoke());

                Assert.Contains("Access to", ex.Message);
                Assert.Contains("is denied by policy (path is not under an allowed root)", ex.Message);
            }
            finally
            {
                Environment.SetEnvironmentVariable("BROKER_ALLOWED_ROOTS", oldRoots);
            }
        }
        finally
        {
            if (Directory.Exists(outsideDir)) Directory.Delete(outsideDir, true);
        }
    }

    public void Dispose()
    {
        if (Directory.Exists(_testDir)) Directory.Delete(_testDir, true);
    }
}

/// <summary>
/// Unit tests for FIX-1: Set-BrokerAdGroupMembership privileged group denylist and exact identity resolution.
/// Note: Full end-to-end user addition against an Active Directory Domain Controller requires
/// an AD DS domain environment and the ActiveDirectory RSAT module. However, the privileged
/// group security denylist and parameter validation can be verified completely offline.
/// </summary>
public class SetBrokerAdGroupMembershipTests
{
    private readonly string _modulePath = Path.Combine(ListDirectoryContentsTests.GetRepoRoot(), "jea", "modules", "Set-BrokerAdGroupMembership.psm1");

    [Theory]
    [InlineData("Domain Admins")]
    [InlineData("Enterprise Admins")]
    [InlineData("Schema Admins")]
    [InlineData("Administrators")]
    [InlineData("Account Operators")]
    [InlineData("DnsAdmins")]
    [InlineData("Domain Controllers")]
    public void PrivilegedGroupChangesAreRefusedBeforeModuleImport(string privilegedGroup)
    {
        using var ps = ListDirectoryContentsTests.CreateTestPowerShell();
        ps.AddScript($"Import-Module '{_modulePath.Replace("'", "''")}'; Set-BrokerAdGroupMembership -GroupName '{privilegedGroup}' -MemberSamAccountName 'testuser' -Action Add");
        var ex = Assert.Throws<RuntimeException>(() => ps.Invoke());
        Assert.Contains("are denied by policy (privileged group)", ex.Message);
    }

    [Fact]
    public void GroupNameWithInvalidCharactersIsRejectedByParameterValidation()
    {
        using var ps = ListDirectoryContentsTests.CreateTestPowerShell();
        ps.AddScript($"Import-Module '{_modulePath.Replace("'", "''")}'; Set-BrokerAdGroupMembership -GroupName 'Group;Drop Table' -MemberSamAccountName 'testuser' -Action Add");
        try
        {
            ps.Invoke();
            Assert.True(ps.HadErrors, "Expected parameter validation error");
            var err = string.Join("; ", ps.Streams.Error);
            Assert.Contains("Cannot validate argument on parameter 'GroupName'", err);
        }
        catch (Exception ex)
        {
            Assert.Contains("GroupName", ex.Message);
        }
    }

    [Fact]
    public void NonPrivilegedGroupNamePassesSecurityGateAndReachesADResolution()
    {
        using var ps = ListDirectoryContentsTests.CreateTestPowerShell();
        // Uses a safe non-privileged group name. If ActiveDirectory RSAT is not present, it passes the
        // denylist and fails only at Import-Module or Get-ADGroup, proving it was NOT blocked by the privileged denylist.
        ps.AddScript($"Import-Module '{_modulePath.Replace("'", "''")}'; Set-BrokerAdGroupMembership -GroupName 'StandardUsers' -MemberSamAccountName 'testuser' -Action Add");
        var ex = Assert.ThrowsAny<Exception>(() => ps.Invoke());
        Assert.DoesNotContain("are denied by policy (privileged group)", ex.Message);
    }

    [Theory]
    [InlineData("RenamedDomainAdmins", "S-1-5-21-99999-512", 0, "privileged group SID")]
    [InlineData("RenamedBuiltinAdmins", "S-1-5-32-544", 0, "privileged group SID")]
    [InlineData("AdminSdHolderProtectedGroup", "S-1-5-21-99999-1234", 1, "adminCount=1 protected group")]
    public void PrivilegedGroupSidsAndAdminCountAreDenied(string name, string sid, int adminCount, string expectedMsg)
    {
        var code = File.ReadAllText(_modulePath);
        code = code.Replace("Import-Module ActiveDirectory -ErrorAction Stop", "");
        code = code.Replace("Get-ADGroup -Identity $GroupName -Properties ObjectGuid, SID, Name, SamAccountName, adminCount, MemberOf -ErrorAction Stop",
            $"[pscustomobject]@{{ Name = '{name}'; SamAccountName = '{name}'; ObjectGuid = [guid]::NewGuid(); SID = [pscustomobject]@{{ Value = '{sid}' }}; adminCount = {adminCount}; MemberOf = @() }}");
        code = code.Replace("Export-ModuleMember -Function Set-BrokerAdGroupMembership", "");

        using var ps = ListDirectoryContentsTests.CreateTestPowerShell();
        ps.AddScript(code + $"\nSet-BrokerAdGroupMembership -GroupName '{name}' -MemberSamAccountName 'testuser' -Action Add");
        var ex = Assert.ThrowsAny<Exception>(() => ps.Invoke());
        Assert.Contains(expectedMsg, ex.Message);
    }
}

/// <summary>
/// Unit tests for H4: Wrapper security boundaries (GPO, Local User, WSUS).
/// </summary>
public class WrapperSecurityBoundariesTests
{
    private static readonly string RepoRoot = ListDirectoryContentsTests.GetRepoRoot();

    [Theory]
    [InlineData("Default Domain Policy")]
    [InlineData("Default Domain Controllers Policy")]
    public void SetBrokerGpoStatusDeniesDefaultPoliciesByName(string defaultGpo)
    {
        var modulePath = Path.Combine(RepoRoot, "jea", "modules", "Set-BrokerGpoStatus.psm1");
        using var ps = ListDirectoryContentsTests.CreateTestPowerShell();
        ps.AddScript($"Import-Module '{modulePath.Replace("'", "''")}'; Set-BrokerGpoStatus -GpoName '{defaultGpo}' -Status 'AllSettingsDisabled'");
        var ex = Assert.Throws<RuntimeException>(() => ps.Invoke());
        Assert.Contains("are denied by policy", ex.Message);
    }

    [Fact]
    public void SetBrokerGpoStatusDeniesDefaultPolicyByGuid()
    {
        var modulePath = Path.Combine(RepoRoot, "jea", "modules", "Set-BrokerGpoStatus.psm1");
        var code = File.ReadAllText(modulePath);
        code = code.Replace("Import-Module GroupPolicy -ErrorAction Stop", "");
        code = code.Replace("Get-GPO -Name $GpoName -ErrorAction Stop", "[pscustomobject]@{ Id = [guid]'31b2f340-016d-11d2-945f-00c04fb984f9'; DisplayName = 'Renamed Default Policy' }");
        code = code.Replace("Export-ModuleMember -Function Set-BrokerGpoStatus", "");

        using var ps = ListDirectoryContentsTests.CreateTestPowerShell();
        ps.AddScript(code + "\nSet-BrokerGpoStatus -GpoName 'Renamed Default Policy' -Status 'AllSettingsDisabled'");
        var ex = Assert.ThrowsAny<Exception>(() => ps.Invoke());
        Assert.Contains("protected GPO GUID", ex.Message);
    }

    [Theory]
    [InlineData("Administrator")]
    [InlineData("Guest")]
    [InlineData("DefaultAccount")]
    public void SetBrokerLocalUserEnabledDeniesBuiltinNames(string name)
    {
        var modulePath = Path.Combine(RepoRoot, "jea", "modules", "Set-BrokerLocalUserEnabled.psm1");
        using var ps = ListDirectoryContentsTests.CreateTestPowerShell();
        ps.AddScript($"Import-Module '{modulePath.Replace("'", "''")}'; Set-BrokerLocalUserEnabled -UserName '{name}' -Enabled 'false'");
        var ex = Assert.Throws<RuntimeException>(() => ps.Invoke());
        Assert.Contains("denied by policy (built-in account)", ex.Message);
    }

    [Theory]
    [InlineData("RenamedAdmin", "S-1-5-21-99999-500")]
    [InlineData("RenamedGuest", "S-1-5-21-99999-501")]
    [InlineData("RenamedDefault", "S-1-5-21-99999-503")]
    public void SetBrokerLocalUserEnabledDeniesBuiltinRidsRegardlessOfName(string name, string sid)
    {
        var modulePath = Path.Combine(RepoRoot, "jea", "modules", "Set-BrokerLocalUserEnabled.psm1");
        var code = File.ReadAllText(modulePath);
        code = code.Replace("Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop", "");
        code = code.Replace("$user = Get-LocalUser -Name $UserName -ErrorAction Stop", $"$user = [pscustomobject]@{{ Name = '{name}'; SID = [pscustomobject]@{{ Value = '{sid}' }}; Enabled = $true }}");
        code = code.Replace("Export-ModuleMember -Function Set-BrokerLocalUserEnabled", "");

        using var ps = ListDirectoryContentsTests.CreateTestPowerShell();
        ps.AddScript(code + $"\nSet-BrokerLocalUserEnabled -UserName '{name}' -Enabled 'false'");
        var ex = Assert.ThrowsAny<Exception>(() => ps.Invoke());
        Assert.Contains("denied by policy (built-in account SID", ex.Message);
    }

    [Fact]
    public void SetBrokerWsusUpdateApprovalDeniesAllComputersTargetGroup()
    {
        var modulePath = Path.Combine(RepoRoot, "jea", "modules", "Set-BrokerWsusUpdateApproval.psm1");
        using var ps = ListDirectoryContentsTests.CreateTestPowerShell();
        ps.AddScript($"Import-Module '{modulePath.Replace("'", "''")}'; Set-BrokerWsusUpdateApproval -UpdateId '11111111-2222-3333-4444-555555555555' -TargetGroup 'All Computers' -Action 'Approve'");
        var ex = Assert.Throws<RuntimeException>(() => ps.Invoke());
        Assert.Contains("Approval to target group 'All Computers' is denied by policy", ex.Message);
    }
}

/// <summary>
/// Unit tests for FIX-7: Startup diagnostics for unconfigured placeholders.
/// </summary>
public class StartupPlaceholderDiagnosticsTests
{
    [Fact]
    public void PlaceholderThumbprintRefusesStartupWithClearError()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Pipe:AllowedSids:0"] = "S-1-5-21-1234567890-1234567890-1234567890-1001",
            ["Elicitation:RequireDistinctApprover"] = "false"
        }).Build();

        var tools = new[]
        {
            new ToolManifest
            {
                ToolId = "tool-with-placeholder",
                Server = new ServerRef { SignatureThumbprint = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }
            }
        };

        var logger = new TestLogger<Worker>();
        bool ok = Worker.CheckConfigurationPlaceholders(config, tools, logger);

        Assert.False(ok);
        Assert.Contains(logger.Errors, e => e.Contains("placeholder thumbprint") && e.Contains("tool-with-placeholder"));
    }

    [Fact]
    public void PlaceholderAllowedSidRefusesStartupWithClearError()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Pipe:AllowedSids:0"] = PlaceholderDiagnostics.PlaceholderSid,
            ["Elicitation:RequireDistinctApprover"] = "false"
        }).Build();

        var tools = new[]
        {
            new ToolManifest
            {
                ToolId = "clean-tool",
                Server = new ServerRef { SignatureThumbprint = "1234567890ABCDEF1234567890ABCDEF12345678" }
            }
        };

        var logger = new TestLogger<Worker>();
        bool ok = Worker.CheckConfigurationPlaceholders(config, tools, logger);

        Assert.False(ok);
        Assert.Contains(logger.Errors, e => e.Contains("Pipe:AllowedSids contains") && e.Contains(PlaceholderDiagnostics.PlaceholderSid));
    }

    [Fact]
    public void DistinctApproverRequiredWithEmptyApproverSidsRefusesStartupWithClearError()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Pipe:AllowedSids:0"] = "S-1-5-21-1234567890-1234567890-1234567890-1001",
            ["Elicitation:RequireDistinctApprover"] = "true"
            // ApproverSids is omitted / empty
        }).Build();

        var tools = new[]
        {
            new ToolManifest
            {
                ToolId = "clean-tool",
                Server = new ServerRef { SignatureThumbprint = "1234567890ABCDEF1234567890ABCDEF12345678" }
            }
        };

        var logger = new TestLogger<Worker>();
        bool ok = Worker.CheckConfigurationPlaceholders(config, tools, logger);

        Assert.False(ok);
        Assert.Contains(logger.Errors, e => e.Contains("Elicitation:RequireDistinctApprover is true, but Elicitation:ApproverSids is empty"));
    }

    [Fact]
    public void OverlappingCallerAndApproverSidsRefusesStartup()
    {
        var overlappingSid = "S-1-5-21-1234567890-1234567890-1234567890-1001";
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Pipe:AllowedSids:0"] = overlappingSid,
            ["Elicitation:RequireDistinctApprover"] = "true",
            ["Elicitation:ApproverSids:0"] = overlappingSid // Violates Invariant 1: Caller SIDs and Approver SIDs must be disjoint!
        }).Build();

        var tools = new[]
        {
            new ToolManifest
            {
                ToolId = "clean-tool",
                Server = new ServerRef { SignatureThumbprint = "1234567890ABCDEF1234567890ABCDEF12345678" }
            }
        };

        var logger = new TestLogger<Worker>();
        bool ok = Worker.CheckConfigurationPlaceholders(config, tools, logger);

        Assert.False(ok);
        Assert.Contains(logger.Errors, e => e.Contains("Invariant 1 violation") && e.Contains("disjoint"));
    }

    [Fact]
    public void FullyConfiguredDeploymentPassesSelfCheck()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Pipe:AllowedSids:0"] = "S-1-5-21-1234567890-1234567890-1234567890-1001",
            ["Elicitation:RequireDistinctApprover"] = "true",
            ["Elicitation:ApproverSids:0"] = "S-1-5-21-1234567890-1234567890-1234567890-1002"
        }).Build();

        var tools = new[]
        {
            new ToolManifest
            {
                ToolId = "clean-tool",
                Server = new ServerRef { SignatureThumbprint = "1234567890ABCDEF1234567890ABCDEF12345678" }
            }
        };

        var logger = new TestLogger<Worker>();
        bool ok = Worker.CheckConfigurationPlaceholders(config, tools, logger);

        Assert.True(ok);
        Assert.Empty(logger.Errors);
    }
}

