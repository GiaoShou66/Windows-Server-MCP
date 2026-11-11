using System.Globalization;
using System.Text;
using Broker.Core;
using Broker.Registry;

namespace Broker.JeaExecution;

/// <summary>
/// Turns tool manifests into JEA .psrc (role capability) and .pssc (session config) files.
///
/// .psrc constrains the exact cmdlet + parameter values natively via ValidateSet /
/// ValidatePattern / ValidateRange so JEA itself rejects out-of-policy calls.
///
/// .pssc runs the session as a gMSA (network/AD tools) or a virtual account (local-only
/// tools), in NoLanguage RestrictedRemoteServer mode with full transcription.
/// Endpoints are consolidated by (risk tier, account type); destructive tools are never
/// consolidated (one endpoint each).
/// </summary>
public sealed class JeaConfigGenerator
{
    private readonly string _outputDir;

    public JeaConfigGenerator(string outputDir) => _outputDir = outputDir;

    /// <summary>Emits one .psrc per tool and one .pssc per distinct endpoint.</summary>
    public IReadOnlyList<string> GenerateAll(IEnumerable<ToolManifest> tools)
    {
        Directory.CreateDirectory(_outputDir);

        // M4: Delete stale .psrc and .pssc files before writing new ones so removed/renamed
        // tools do not leave lingering JEA configurations in the generated directory.
        foreach (var existing in Directory.GetFiles(_outputDir, "*.psrc").Concat(Directory.GetFiles(_outputDir, "*.pssc")))
        {
            try { File.Delete(existing); } catch { }
        }

        var written = new List<string>();
        var byEndpoint = new Dictionary<string, List<ToolManifest>>(StringComparer.Ordinal);

        foreach (var tool in tools)
        {
            var psrcPath = Path.Combine(_outputDir, $"{tool.JeaMapping.RoleCapabilityName}.psrc");
            File.WriteAllText(psrcPath, BuildPsrc(tool));
            written.Add(psrcPath);

            if (!byEndpoint.TryGetValue(tool.JeaMapping.EndpointName, out var list))
                byEndpoint[tool.JeaMapping.EndpointName] = list = new();
            list.Add(tool);
        }

        foreach (var (endpoint, endpointTools) in byEndpoint)
        {
            var psscPath = Path.Combine(_outputDir, $"{endpoint}.pssc");
            File.WriteAllText(psscPath, BuildPssc(endpoint, endpointTools));
            written.Add(psscPath);
        }

        return written;
    }

    private static string BuildPsrc(ToolManifest tool)
    {
        var paramConstraints = tool.Parameters.Select(BuildParameterConstraint);
        var paramBlock = string.Join(",\n                    ", paramConstraints);
        var paramsClause = tool.Parameters.Count == 0
            ? ""
            : $"\n                Parameters = @(\n                    {paramBlock}\n                )";

        if (string.IsNullOrWhiteSpace(tool.JeaMapping.ModuleName))
            throw new InvalidOperationException(
                $"Tool {tool.ToolId}: jeaMapping.moduleName is required so the .psrc can import the cmdlet's module.");

        var externalCommands = tool.JeaMapping.ExternalCommands is { Count: > 0 } cmds
            ? string.Join(", ", cmds.Select(c => $"'{Escape(c)}'"))
            : "";

        return $$"""
        @{
            GUID = '{{Guid.NewGuid()}}'
            Author = 'mcp-broker-generator'
            CompanyName = 'internal'
            Copyright = ''
            Description = '{{Escape(tool.Description)}}'
            ModulesToImport = @('{{Escape(tool.JeaMapping.ModuleName)}}')
            VisibleCmdlets = @(
            @{
                Name = '{{tool.JeaMapping.Cmdlet}}'{{paramsClause}}
            }
            )
            VisibleExternalCommands = @({{externalCommands}})
            VisibleFunctions = @()
            VisibleAliases = @()
            VisibleProviders = @()
        }
        """;
    }

    private static string BuildParameterConstraint(ToolParameter p)
    {
        var a = p.Allowlist;
        if (a.EnumValues is { Count: > 0 } values)
        {
            var validated = string.Join(",", values.Select(v => $"'{Escape(v)}'"));
            return $"@{{ Name = '{p.Name}'; ValidateSet = {validated} }}";
        }
        if (a.RegexPattern is { } pattern)
            return $"@{{ Name = '{p.Name}'; ValidatePattern = '{Escape(pattern)}' }}";
        if (a.Range is { } range)
        {
            // Invariant formatting: under a comma-decimal culture "1.5" would be written "1,5"
            // and read back by PowerShell as two array elements, silently changing the range.
            var min = range.Min.ToString(CultureInfo.InvariantCulture);
            var max = range.Max.ToString(CultureInfo.InvariantCulture);
            return $"@{{ Name = '{p.Name}'; ValidateRange = {min},{max} }}";
        }

        // maxLength-only: no native JEA equivalent, enforced broker-side by ParameterValidator
        return $"@{{ Name = '{p.Name}' }}";
    }

    private static string BuildPssc(string endpointName, IReadOnlyList<ToolManifest> tools)
    {
        // Account model: a mixed endpoint should not exist by policy, but if tools disagree
        // we take the strongest identity requirement (gMSA wins) and surface it for review.
        var usesGmsa = tools.Any(t => t.JeaMapping.UseGmsa);
        var gmsa = tools.Select(t => t.JeaMapping.GmsaAccount).FirstOrDefault(g => !string.IsNullOrEmpty(g));

        // RoleDefinitions keys MUST be real security principals (a group/user), not arbitrary
        // labels. All tools on one endpoint share one access group; mismatch is a config error.
        var accessGroups = tools.Select(t => t.JeaMapping.AccessGroup)
            .Where(g => !string.IsNullOrWhiteSpace(g))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (accessGroups.Count == 0)
            throw new InvalidOperationException(
                $"Endpoint {endpointName}: no jeaMapping.accessGroup set; RoleDefinitions needs a real group/account.");
        if (accessGroups.Count > 1)
            throw new InvalidOperationException(
                $"Endpoint {endpointName}: tools disagree on accessGroup ({string.Join(", ", accessGroups)}). One endpoint, one group.");

        ValidateAccessGroupNotBroad(endpointName, accessGroups[0]);

        var roleCapabilities = string.Join(", ", tools
            .Select(t => t.JeaMapping.RoleCapabilityName)
            .Distinct(StringComparer.Ordinal)
            .Select(rc => $"'{Escape(rc)}'"));
        var roleDefs = $"'{Escape(accessGroups[0])}' = @{{ RoleCapabilities = @({roleCapabilities}) }}";

        string accountBlock;
        if (usesGmsa)
        {
            // An empty gMSA account silently produces a session config that fails at
            // registration or, worse, runs as the wrong identity. Fail at generation time.
            if (string.IsNullOrWhiteSpace(gmsa))
                throw new InvalidOperationException(
                    $"Endpoint {endpointName}: useGmsa is true but no gmsaAccount is set; the session cannot be bound to an identity.");
            accountBlock = $$"""
                RunAsVirtualAccount = $false
                GroupManagedServiceAccount = '{{Escape(gmsa)}}'
                """;
        }
        else
        {
            accountBlock = BuildVirtualAccountBlock(endpointName, tools);
        }

        return $$"""
        @{
            SchemaVersion = '2.0.0.0'
            GUID = '{{Guid.NewGuid()}}'
            Author = 'mcp-broker-generator'
            Description = 'MCP broker endpoint: {{endpointName}}'
            SessionType = 'RestrictedRemoteServer'
            {{accountBlock}}
            TranscriptDirectory = 'C:\McpBroker\Transcripts'
            RoleDefinitions = @{
        {{roleDefs}}
            }
            LanguageMode = 'NoLanguage'
            ExecutionPolicy = 'Restricted'
            MountUserDrive = $false
        }
        """;
    }

    /// <summary>
    /// Emits the virtual-account block with an ALWAYS-explicit group list.
    ///
    /// JEA's documented default for a virtual account is membership in the local
    /// Administrators group (Domain Admins on a domain controller) when
    /// RunAsVirtualAccountGroups is omitted. Omitting it therefore granted every local
    /// endpoint the strongest possible local privilege by accident. Requiring the key to be
    /// present makes the grant a deliberate, reviewable decision: an empty list means a
    /// plain virtual account, and Administrators must be written down on purpose.
    /// </summary>
    private static string BuildVirtualAccountBlock(string endpointName, IReadOnlyList<ToolManifest> tools)
    {
        var declaring = tools.Select(t => t.JeaMapping.VirtualAccountGroups)
            .Where(g => g is not null)
            .ToList();

        // Absent on every tool: refuse rather than inherit JEA's Administrators default.
        if (declaring.Count == 0)
            throw new InvalidOperationException(
                $"Endpoint {endpointName}: virtual-account tools must declare jeaMapping.virtualAccountGroups " +
                "(use @() for none). Omitting it makes JEA grant the local Administrators group by default.");

        var groups = declaring
            .SelectMany(g => g!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var groupsClause = $"\n            RunAsVirtualAccountGroups = @({string.Join(", ", groups.Select(g => $"'{Escape(g)}'"))})";

        return $"RunAsVirtualAccount = $true{groupsClause}";
    }

    private static void ValidateAccessGroupNotBroad(string endpointName, string group)
    {
        var normalized = group.Trim();
        var simpleName = normalized.Contains('\\') ? normalized.Substring(normalized.LastIndexOf('\\') + 1) : normalized;

        var disallowedSimpleNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Users", "Domain Users", "Authenticated Users", "Everyone", "Interactive"
        };

        var disallowedFullNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "BUILTIN\\Users",
            "Users",
            "Domain Users",
            "Authenticated Users",
            "NT AUTHORITY\\Authenticated Users",
            "Everyone",
            "BUILTIN\\Everyone",
            "Interactive",
            "NT AUTHORITY\\Interactive",
            "S-1-1-0",
            "S-1-5-11",
            "S-1-5-4",
            "S-1-5-32-545"
        };

        if (disallowedSimpleNames.Contains(simpleName) || disallowedFullNames.Contains(normalized))
        {
            throw new InvalidOperationException(
                $"Endpoint {endpointName}: accessGroup '{group}' is a broad principal and cannot be used in RoleDefinitions. " +
                "Invariant 3 mandates that JEA RoleDefinitions grant ONLY a dedicated service group whose sole member is the broker service account.");
        }
    }

    private static string Escape(string s) => s.Replace("'", "''");
}
