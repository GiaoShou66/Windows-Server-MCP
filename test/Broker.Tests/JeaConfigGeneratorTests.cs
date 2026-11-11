using Broker.JeaExecution;
using Broker.Registry;
using Xunit;

namespace Broker.Tests;

/// <summary>
/// Covers JeaConfigGenerator — previously validated only once, manually, via the
/// `generate-jea` CLI against the real manifest (which caught the RiskTier JSON collision
/// bug). These tests cover the generator's actual decision logic: endpoint consolidation,
/// the native ValidateSet/ValidatePattern/ValidateRange emission, and the validation guards
/// (missing moduleName/accessGroup, mismatched accessGroup) that make a misconfigured
/// manifest fail loudly at generation time instead of producing a broken JEA endpoint.
/// </summary>
public sealed class JeaConfigGeneratorTests : IDisposable
{
    private readonly string _outDir;
    public JeaConfigGeneratorTests() => _outDir = Path.Combine(Path.GetTempPath(), $"mcp-test-jea-{Guid.NewGuid():N}");

    private static ToolManifest Tool(
        string id, string endpoint, string roleCap, string cmdlet, string moduleName, string accessGroup,
        bool useGmsa = false, string? gmsa = null, List<ToolParameter>? parameters = null,
        List<string>? virtualAccountGroups = null) => new()
    {
        ToolId = id,
        Description = $"desc-{id}",
        JeaMapping = new JeaMapping
        {
            EndpointName = endpoint,
            RoleCapabilityName = roleCap,
            Cmdlet = cmdlet,
            ModuleName = moduleName,
            AccessGroup = accessGroup,
            UseGmsa = useGmsa,
            GmsaAccount = gmsa,
            VirtualAccountGroups = virtualAccountGroups ?? new List<string>()
        },
        Parameters = parameters ?? new()
    };

    [Fact]
    public void GeneratesOnePsrcPerToolAndOnePsscPerEndpoint()
    {
        var tools = new[]
        {
            Tool("t1", "ep.read", "rc1", "Get-A", "Get-A", "GROUP"),
            Tool("t2", "ep.read", "rc2", "Get-B", "Get-B", "GROUP"),
            Tool("t3", "ep.write", "rc3", "Set-A", "Set-A", "GROUP")
        };

        var generator = new JeaConfigGenerator(_outDir);
        var written = generator.GenerateAll(tools);

        Assert.Equal(5, written.Count); // 3 .psrc + 2 distinct .pssc (ep.read, ep.write)
        Assert.Contains(written, f => f.EndsWith("rc1.psrc"));
        Assert.Contains(written, f => f.EndsWith("rc2.psrc"));
        Assert.Contains(written, f => f.EndsWith("rc3.psrc"));
        Assert.Contains(written, f => f.EndsWith("ep.read.pssc"));
        Assert.Contains(written, f => f.EndsWith("ep.write.pssc"));
    }

    [Fact]
    public void ConsolidatedEndpointReferencesBothRoleCapabilities()
    {
        var tools = new[]
        {
            Tool("t1", "ep.read", "rc1", "Get-A", "Get-A", "GROUP"),
            Tool("t2", "ep.read", "rc2", "Get-B", "Get-B", "GROUP")
        };

        new JeaConfigGenerator(_outDir).GenerateAll(tools);
        var pssc = File.ReadAllText(Path.Combine(_outDir, "ep.read.pssc"));

        Assert.Contains("'rc1'", pssc);
        Assert.Contains("'rc2'", pssc);
        Assert.Contains("'GROUP' = @{", pssc); // RoleDefinitions keyed on the real access group
    }

    [Fact]
    public void MismatchedAccessGroupOnSameEndpointThrows()
    {
        var tools = new[]
        {
            Tool("t1", "ep.shared", "rc1", "Get-A", "Get-A", "GROUP-A"),
            Tool("t2", "ep.shared", "rc2", "Get-B", "Get-B", "GROUP-B")
        };

        var ex = Assert.Throws<InvalidOperationException>(() => new JeaConfigGenerator(_outDir).GenerateAll(tools));
        Assert.Contains("accessGroup", ex.Message);
    }

    [Fact]
    public void MissingAccessGroupThrows()
    {
        var tool = Tool("t1", "ep.read", "rc1", "Get-A", "Get-A", accessGroup: "");

        var ex = Assert.Throws<InvalidOperationException>(() => new JeaConfigGenerator(_outDir).GenerateAll([tool]));
        Assert.Contains("accessGroup", ex.Message);
    }

    [Fact]
    public void MissingModuleNameThrows()
    {
        var tool = Tool("t1", "ep.read", "rc1", "Get-A", moduleName: "", accessGroup: "GROUP");

        var ex = Assert.Throws<InvalidOperationException>(() => new JeaConfigGenerator(_outDir).GenerateAll([tool]));
        Assert.Contains("moduleName", ex.Message);
    }

    [Fact]
    public void PsrcImportsTheWrapperModule()
    {
        var tool = Tool("t1", "ep.read", "rc1", "Get-A", "MyModule.Get-A", "GROUP");

        new JeaConfigGenerator(_outDir).GenerateAll([tool]);
        var psrc = File.ReadAllText(Path.Combine(_outDir, "rc1.psrc"));

        Assert.Contains("ModulesToImport = @('MyModule.Get-A')", psrc);
        Assert.Contains("Name = 'Get-A'", psrc);
    }

    [Fact]
    public void ParameterConstraintsEmitNativeValidation()
    {
        var tool = Tool("t1", "ep.read", "rc1", "Get-A", "Get-A", "GROUP", parameters: new()
        {
            new ToolParameter { Name = "Mode", Allowlist = new ParameterAllowlist { EnumValues = new() { "a", "b" } } },
            new ToolParameter { Name = "Pattern", Allowlist = new ParameterAllowlist { RegexPattern = "^[a-z]+$" } },
            new ToolParameter { Name = "Days", Allowlist = new ParameterAllowlist { Range = new ParamRange { Min = 1, Max = 30 } } },
            new ToolParameter { Name = "Note", Allowlist = new ParameterAllowlist { MaxLength = 100 } }
        });

        new JeaConfigGenerator(_outDir).GenerateAll([tool]);
        var psrc = File.ReadAllText(Path.Combine(_outDir, "rc1.psrc"));

        Assert.Contains("ValidateSet = 'a','b'", psrc);
        Assert.Contains("ValidatePattern = '^[a-z]+$'", psrc);
        Assert.Contains("ValidateRange = 1,30", psrc);
        // maxLength-only has no native JEA equivalent — just the bare parameter name.
        Assert.Contains("Name = 'Note'", psrc);
    }

    /// <summary>
    /// The emitted range must not depend on the culture of the host that runs generate-jea.
    /// Under a comma-decimal culture 1.5 used to be written "1,5", which PowerShell reads as
    /// two array elements — a different range from the one the broker enforces.
    /// </summary>
    [Fact]
    public void ValidateRangeIsEmittedWithInvariantNumberFormatting()
    {
        var tool = Tool("t1", "ep.read", "rc1", "Get-A", "Get-A", "GROUP", parameters: new()
        {
            new ToolParameter { Name = "Ratio", Allowlist = new ParameterAllowlist { Range = new ParamRange { Min = -1.5, Max = 30.25 } } }
        });

        var original = System.Globalization.CultureInfo.CurrentCulture;
        try
        {
            System.Globalization.CultureInfo.CurrentCulture = new System.Globalization.CultureInfo("de-DE");
            new JeaConfigGenerator(_outDir).GenerateAll([tool]);
        }
        finally
        {
            System.Globalization.CultureInfo.CurrentCulture = original;
        }

        var psrc = File.ReadAllText(Path.Combine(_outDir, "rc1.psrc"));
        Assert.Contains("ValidateRange = -1.5,30.25 }", psrc);
    }

    [Fact]
    public void GmsaEndpointEmitsGroupManagedServiceAccountNotVirtualAccount()
    {
        var tool = Tool("t1", "ep.ad", "rc1", "Get-ADUser", "Get-ADUser", "GROUP",
            useGmsa: true, gmsa: "CONTOSO\\McpBrokerSvc$");

        new JeaConfigGenerator(_outDir).GenerateAll([tool]);
        var pssc = File.ReadAllText(Path.Combine(_outDir, "ep.ad.pssc"));

        Assert.Contains("RunAsVirtualAccount = $false", pssc);
        Assert.Contains("GroupManagedServiceAccount = 'CONTOSO\\McpBrokerSvc$'", pssc);
    }

    [Fact]
    public void LocalEndpointEmitsVirtualAccount()
    {
        var tool = Tool("t1", "ep.local", "rc1", "Get-Thing", "Get-Thing", "GROUP", useGmsa: false);

        new JeaConfigGenerator(_outDir).GenerateAll([tool]);
        var pssc = File.ReadAllText(Path.Combine(_outDir, "ep.local.pssc"));

        Assert.Contains("RunAsVirtualAccount = $true", pssc);
        Assert.DoesNotContain("GroupManagedServiceAccount", pssc);
    }

    [Fact]
    public void ExternalCommandsAreEmittedIntoVisibleExternalCommands()
    {
        var tool = Tool("t1", "ep.read", "rc1", "Get-BrokerLocalSecurityPolicy", "Get-BrokerLocalSecurityPolicy", "GROUP");
        tool.JeaMapping.ExternalCommands = new List<string> { "secedit.exe" };

        new JeaConfigGenerator(_outDir).GenerateAll([tool]);
        var psrc = File.ReadAllText(Path.Combine(_outDir, "rc1.psrc"));

        Assert.Contains("VisibleExternalCommands = @('secedit.exe')", psrc);
    }

    [Fact]
    public void NoExternalCommandsEmitsEmptyVisibleExternalCommands()
    {
        var tool = Tool("t1", "ep.read", "rc1", "Get-A", "Get-A", "GROUP");

        new JeaConfigGenerator(_outDir).GenerateAll([tool]);
        var psrc = File.ReadAllText(Path.Combine(_outDir, "rc1.psrc"));

        Assert.Contains("VisibleExternalCommands = @()", psrc);
    }

    [Fact]
    public void MultipleExternalCommandsAreAllEmitted()
    {
        var tool = Tool("t1", "ep.read", "rc1", "Get-A", "Get-A", "GROUP");
        tool.JeaMapping.ExternalCommands = new List<string> { "secedit.exe", "auditpol.exe" };

        new JeaConfigGenerator(_outDir).GenerateAll([tool]);
        var psrc = File.ReadAllText(Path.Combine(_outDir, "rc1.psrc"));

        Assert.Contains("VisibleExternalCommands = @('secedit.exe', 'auditpol.exe')", psrc);
    }

    [Theory]
    [InlineData("BUILTIN\\Users")]
    [InlineData("Users")]
    [InlineData("Domain Users")]
    [InlineData("CONTOSO\\Domain Users")]
    [InlineData("Authenticated Users")]
    [InlineData("NT AUTHORITY\\Authenticated Users")]
    [InlineData("Everyone")]
    [InlineData("Interactive")]
    [InlineData("NT AUTHORITY\\Interactive")]
    public void RejectBroadAccessGroupsAtGenerationTime(string broadGroup)
    {
        var tool = Tool("t1", "ep.read", "rc1", "Get-A", "Get-A", accessGroup: broadGroup);

        var ex = Assert.Throws<InvalidOperationException>(() => new JeaConfigGenerator(_outDir).GenerateAll([tool]));
        Assert.Contains("broad principal", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DeletesStalePsrcAndPsscFiles()
    {
        Directory.CreateDirectory(_outDir);
        var stalePsrc = Path.Combine(_outDir, "stale-tool.psrc");
        var stalePssc = Path.Combine(_outDir, "stale-endpoint.pssc");
        File.WriteAllText(stalePsrc, "stale");
        File.WriteAllText(stalePssc, "stale");

        var tool = Tool("t1", "ep.read", "rc1", "Get-A", "Get-A", accessGroup: "CONTOSO\\McpBrokerSvcGroup");
        new JeaConfigGenerator(_outDir).GenerateAll([tool]);

        Assert.False(File.Exists(stalePsrc), "Stale .psrc was not deleted");
        Assert.False(File.Exists(stalePssc), "Stale .pssc was not deleted");
    }

    public void Dispose()
    {
        if (Directory.Exists(_outDir)) Directory.Delete(_outDir, recursive: true);
    }
}
