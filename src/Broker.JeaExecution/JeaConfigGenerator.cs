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

    private static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(1);

    private static System.Text.RegularExpressions.Regex Identifier(string pattern) =>
        new(pattern, System.Text.RegularExpressions.RegexOptions.CultureInvariant, RegexTimeout);

    // These strings are interpolated into PowerShell data files that decide which cmdlets JEA exposes
    // (and, for RoleCapabilityName, into a file name). They must be plain identifiers.
    private static readonly System.Text.RegularExpressions.Regex CmdletName = Identifier(@"^[A-Za-z][A-Za-z0-9]*-[A-Za-z][A-Za-z0-9]*\z");
    private static readonly System.Text.RegularExpressions.Regex ModuleName = Identifier(@"^[A-Za-z0-9][A-Za-z0-9._-]*\z");
    private static readonly System.Text.RegularExpressions.Regex RoleCapability = Identifier(@"^[A-Za-z][A-Za-z0-9]*\z");
    private static readonly System.Text.RegularExpressions.Regex EndpointId = Identifier(@"^[A-Za-z0-9][A-Za-z0-9._-]*\z");
    private static readonly System.Text.RegularExpressions.Regex Principal = Identifier(@"^([A-Za-z0-9._ -]+\\)?[A-Za-z0-9._ $-]+\z");
    private static readonly System.Text.RegularExpressions.Regex GmsaName = Identifier(@"^([A-Za-z0-9._-]+\\)?[A-Za-z0-9._-]+\$?\z");
    private static readonly System.Text.RegularExpressions.Regex ExeName = Identifier(@"^[A-Za-z0-9][A-Za-z0-9._-]*\.exe\z");
    private static readonly System.Text.RegularExpressions.Regex ParameterId = Identifier(@"^[A-Za-z][A-Za-z0-9]*\z");

    /// <summary>
    /// Refuses any manifest value that is not a plain identifier. The message names the tool and the
    /// field but never repeats the value.
    /// </summary>
    internal static void ValidateIdentifiers(ToolManifest tool)
    {
        static void Check(ToolManifest t, string field, string? value, System.Text.RegularExpressions.Regex rx)
        {
            if (value is null || !rx.IsMatch(value))
                throw new InvalidOperationException($"Tool {t.ToolId}: jeaMapping value '{field}' is missing or is not a plain identifier.");
        }

        var m = tool.JeaMapping;
        Check(tool, "cmdlet", m.Cmdlet, CmdletName);
        Check(tool, "moduleName", m.ModuleName, ModuleName);
        Check(tool, "roleCapabilityName", m.RoleCapabilityName, RoleCapability);
        Check(tool, "endpointName", m.EndpointName, EndpointId);
        Check(tool, "accessGroup", m.AccessGroup, Principal);

        if (m.UseGmsa) Check(tool, "gmsaAccount", m.GmsaAccount, GmsaName);
        foreach (var g in m.VirtualAccountGroups ?? new()) Check(tool, "virtualAccountGroups", g, Principal);
        foreach (var c in m.ExternalCommands ?? new()) Check(tool, "externalCommands", c, ExeName);

        foreach (var p in tool.Parameters)
        {
            Check(tool, "parameter name", p.Name, ParameterId);
            if (p.Allowlist.Range is { } r &&
                (!double.IsFinite(r.Min) || !double.IsFinite(r.Max) || r.Min > r.Max))
                throw new InvalidOperationException($"Tool {tool.ToolId}: parameter '{p.Name}' has an invalid range.");
        }
    }

    /// <summary>Emits one .psrc per tool and one .pssc per distinct endpoint.</summary>
    public IReadOnlyList<string> GenerateAll(IEnumerable<ToolManifest> tools)
    {
        // Validate everything before touching the disk: one bad tool stops the whole run.
        var all = tools.ToList();
        foreach (var tool in all) ValidateIdentifiers(tool);

        Directory.CreateDirectory(_outputDir);
        var written = new List<string>();
        var byEndpoint = new Dictionary<string, List<ToolManifest>>(StringComparer.Ordinal);

        foreach (var tool in all)
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
            return $"@{{ Name = '{p.Name}'; ValidateRange = {range.Min.ToString("R", CultureInfo.InvariantCulture)},{range.Max.ToString("R", CultureInfo.InvariantCulture)} }}";

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

        var roleCapabilities = string.Join(", ", tools
            .Select(t => t.JeaMapping.RoleCapabilityName)
            .Distinct(StringComparer.Ordinal)
            .Select(rc => $"'{Escape(rc)}'"));
        var roleDefs = $"'{Escape(accessGroups[0])}' = @{{ RoleCapabilities = @({roleCapabilities}) }}";

        var accountBlock = usesGmsa
            ? $$"""
                RunAsVirtualAccount = $false
                GroupManagedServiceAccount = '{{gmsa}}'
                """
            : BuildVirtualAccountBlock(tools);

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

    private static string BuildVirtualAccountBlock(IReadOnlyList<ToolManifest> tools)
    {
        var groups = tools
            .SelectMany(t => t.JeaMapping.VirtualAccountGroups ?? new List<string>())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var groupsClause = groups.Count == 0
            ? ""
            : $"\n            RunAsVirtualAccountGroups = @({string.Join(", ", groups.Select(g => $"'{Escape(g)}'"))})";

        return $"RunAsVirtualAccount = $true{groupsClause}";
    }

    private static string Escape(string s) => s.Replace("'", "''");
}
