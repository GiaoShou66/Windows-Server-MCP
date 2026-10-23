using System.Management.Automation;
using System.Management.Automation.Language;
using System.Text.RegularExpressions;
using Xunit;

namespace Broker.Tests;

/// <summary>
/// Executes Test-WdacEnforcementReadiness for real, through the in-process PowerShell engine. The
/// function is pure (every fact is a parameter), so this needs neither Windows nor a WDAC policy.
/// It does NOT test setup-wdac.ps1 end to end: New-CIPolicy, Get-WinEvent and CiTool need Windows.
/// </summary>
public class WdacReadinessTests
{
    private static readonly DateTime Now = new(2030, 6, 1, 12, 0, 0, DateTimeKind.Utc);
    private const string Expected = "ENFORCE HOST1";
    private const string Hash = "ABCDEF0123456789";

    private static PSObject State(string mode = "Audit", string hash = Hash, string? started = null, string policyId = "11111111-2222-3333-4444-555555555555")
    {
        var o = new PSObject();
        o.Properties.Add(new PSNoteProperty("Mode", mode));
        o.Properties.Add(new PSNoteProperty("AuditXmlHash", hash));
        o.Properties.Add(new PSNoteProperty("AuditStartedUtc", started ?? Now.AddDays(-10).ToString("o")));
        o.Properties.Add(new PSNoteProperty("PolicyId", policyId));
        return o;
    }

    private static (bool Ready, string[] Reasons) Check(
        object? state, string currentHash = Hash, int audit = 0, int loaded = 3, int minDays = 7,
        string confirm = Expected, bool short_ = false, bool findings = false, bool assume = false)
    {
        using var ps = PowerShell.Create();
        ps.AddCommand("Import-Module").AddParameter("Name", RepoPaths.Combine("deploy", "WdacReadiness.psm1")).AddParameter("Force");
        ps.Invoke();
        Assert.False(ps.HadErrors, string.Join("; ", ps.Streams.Error.Select(e => e.ToString())));

        ps.Commands.Clear();
        ps.AddCommand("Test-WdacEnforcementReadiness")
            .AddParameter("State", state)
            .AddParameter("CurrentAuditXmlHash", currentHash)
            .AddParameter("NowUtc", Now)
            .AddParameter("AuditEventCount", audit)
            .AddParameter("PolicyLoadedEventCount", loaded)
            .AddParameter("MinAuditDays", minDays)
            .AddParameter("ConfirmationText", confirm)
            .AddParameter("ExpectedConfirmationText", Expected);
        if (short_) ps.AddParameter("AcceptShortAudit");
        if (findings) ps.AddParameter("AcceptAuditFindings");
        if (assume) ps.AddParameter("AssumeAuditPolicyActive");

        var result = ps.Invoke();
        Assert.False(ps.HadErrors, string.Join("; ", ps.Streams.Error.Select(e => e.ToString())));
        var obj = Assert.Single(result);
        var reasons = ((IEnumerable<object>)obj.Properties["Reasons"].Value!).Select(r => r.ToString()!).ToArray();
        return ((bool)obj.Properties["Ready"].Value!, reasons);
    }

    [Fact]
    public void AnAuditedUnchangedConfirmedPolicyIsReady()
    {
        var (ready, reasons) = Check(State());
        Assert.True(ready, string.Join(" | ", reasons));
        Assert.Empty(reasons);
    }

    [Fact]
    public void NoAuditStateIsNeverReady()
    {
        var (ready, reasons) = Check(null);
        Assert.False(ready);
        Assert.Contains(reasons, r => r.Contains("No audit state"));
    }

    [Fact]
    public void AStateThatIsNotAuditIsNeverReady()
    {
        var (ready, reasons) = Check(State(mode: "EnforcedBuilt"));
        Assert.False(ready);
        Assert.Contains(reasons, r => r.Contains("not 'Audit'"));
    }

    [Theory]
    [InlineData("DIFFERENT")]
    [InlineData("")]
    public void APolicyThatChangedSinceTheAuditIsNeverReady(string recordedHash)
    {
        var (ready, reasons) = Check(State(hash: recordedHash));
        Assert.False(ready);
        Assert.Contains(reasons, r => r.Contains("differs"));
    }

    [Fact]
    public void HashComparisonIgnoresCaseOnly()
    {
        Assert.True(Check(State(hash: Hash.ToLowerInvariant())).Ready);
        Assert.False(Check(State(hash: Hash + "0")).Ready);
    }

    [Fact]
    public void ABriefAuditIsRefusedUnlessExplicitlyAccepted()
    {
        var recent = State(started: Now.AddDays(-3).ToString("o"));

        var refused = Check(recent);
        Assert.False(refused.Ready);
        Assert.Contains(refused.Reasons, r => r.Contains("auditing for 3"));

        Assert.True(Check(recent, short_: true).Ready);
    }

    [Fact]
    public void TheMinimumAuditPeriodBoundaryIsInclusive()
    {
        Assert.True(Check(State(started: Now.AddDays(-7).ToString("o"))).Ready);
        Assert.False(Check(State(started: Now.AddDays(-7).AddSeconds(1).ToString("o"))).Ready);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not a date")]
    public void AnUnreadableStartTimeIsNeverReadyAndCannotBeOverridden(string started)
    {
        var (ready, reasons) = Check(State(started: started), short_: true, findings: true, assume: true);
        Assert.False(ready);
        Assert.Contains(reasons, r => r.Contains("audit start time"));
    }

    [Fact]
    public void AStartTimeInTheFutureIsNeverReady()
    {
        var (ready, reasons) = Check(State(started: Now.AddDays(1).ToString("o")), short_: true);
        Assert.False(ready);
        Assert.Contains(reasons, r => r.Contains("future"));
    }

    [Fact]
    public void WouldHaveBeenBlockedEventsBlockUnlessAccepted()
    {
        var refused = Check(State(), audit: 4);
        Assert.False(refused.Ready);
        Assert.Contains(refused.Reasons, r => r.Contains("4 file(s) would have been blocked"));

        Assert.True(Check(State(), audit: 4, findings: true).Ready);
    }

    [Fact]
    public void AnUnreadableEventLogCannotBeOverridden()
    {
        var (ready, reasons) = Check(State(), audit: -1, short_: true, findings: true, assume: true);
        Assert.False(ready);
        Assert.Contains(reasons, r => r.Contains("could not be read"));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void NoEvidenceThePolicyWasLoadedBlocksUnlessAssumed(int loaded)
    {
        var refused = Check(State(), loaded: loaded);
        Assert.False(refused.Ready);
        Assert.Contains(refused.Reasons, r => r.Contains("no evidence"));

        Assert.True(Check(State(), loaded: loaded, assume: true).Ready);
    }

    [Theory]
    [InlineData("")]
    [InlineData("ENFORCE")]
    [InlineData("enforce host1")]
    [InlineData("ENFORCE HOST1 ")]
    [InlineData("ENFORCE OTHERHOST")]
    public void TheTypedConfirmationMustMatchExactly(string typed)
    {
        var (ready, reasons) = Check(State(), confirm: typed);
        Assert.False(ready);
        Assert.Contains(reasons, r => r.Contains("Typed confirmation"));
    }

    [Fact]
    public void EveryFailingConditionIsReportedNotJustTheFirst()
    {
        var (ready, reasons) = Check(State(mode: "Other", hash: "x", started: Now.AddDays(-1).ToString("o")),
            audit: 2, loaded: 0, confirm: "");
        Assert.False(ready);
        Assert.True(reasons.Length >= 5, string.Join(" | ", reasons));
    }

    [Fact]
    public void OverridesNeverRescueAnUnrelatedFailure()
    {
        var (ready, _) = Check(State(hash: "tampered"), short_: true, findings: true, assume: true);
        Assert.False(ready);

        Assert.False(Check(State(), short_: true, findings: true, assume: true, confirm: "").Ready);
        Assert.False(Check(null, short_: true, findings: true, assume: true).Ready);
    }
}

public class DeploymentScriptStaticTests
{
    private static IEnumerable<string> Scripts() =>
        Directory.GetFiles(RepoPaths.Combine("deploy"), "*.ps*1")
            .Concat(Directory.GetFiles(RepoPaths.Combine("jea", "modules"), "*.psm1"));

    [Fact]
    public void EveryDeploymentScriptAndWrapperParsesWithoutErrors()
    {
        var files = Scripts().ToList();
        Assert.True(files.Count > 50);

        foreach (var file in files)
        {
            Parser.ParseFile(file, out _, out var errors);
            Assert.True(errors.Length == 0, $"{Path.GetFileName(file)}: {string.Join("; ", errors.Select(e => $"{e.Extent.StartLineNumber}: {e.Message}"))}");
        }
    }

    private static string WdacScript() => File.ReadAllText(RepoPaths.Combine("deploy", "setup-wdac.ps1"));

    [Fact]
    public void TheWdacScriptNeverDeploysAPolicyItself()
    {
        // CiTool is mentioned only as text for the operator (Write-Host and the rollback here-string).
        // Look at the syntax tree, not the text: no command in the script may BE CiTool.
        var ast = Parser.ParseFile(RepoPaths.Combine("deploy", "setup-wdac.ps1"), out _, out _);
        var invoked = ast.FindAll(a => a is CommandAst, true).Cast<CommandAst>()
            .Select(c => c.GetCommandName() ?? "")
            .Where(n => n.StartsWith("citool", StringComparison.OrdinalIgnoreCase)
                     || n.Equals("Start-Process", StringComparison.OrdinalIgnoreCase)
                     || n.Equals("Invoke-Expression", StringComparison.OrdinalIgnoreCase))
            .ToList();
        Assert.Empty(invoked);
        Assert.DoesNotMatch(@"(?i)Copy-Item[^\r\n]*CiPolicies", WdacScript());
    }

    [Fact]
    public void TheWdacScriptMergesABasePolicyAndRefusesToRunWithoutOne()
    {
        var s = WdacScript();
        Assert.Contains("Merge-CIPolicy", s);
        Assert.Matches(@"(?s)if \(-not \(Test-Path -LiteralPath \$BasePolicyXml.*?throw", s);
    }

    [Fact]
    public void EnforcementPromotesTheAuditedArtifactAfterTheReadinessGate()
    {
        var s = WdacScript();
        int gate = s.IndexOf("Test-WdacEnforcementReadiness `", StringComparison.Ordinal);
        int refuse = s.IndexOf("throw 'Enforcement refused.", StringComparison.Ordinal);
        int dropAudit = s.IndexOf("Set-RuleOption -FilePath $enforcedXml -Option 3 -Delete", StringComparison.Ordinal);
        int bootAudit = s.IndexOf("Set-RuleOption -FilePath $enforcedXml -Option 10", StringComparison.Ordinal);
        int fromAudit = s.IndexOf("Copy-Item -LiteralPath $auditXml -Destination $enforcedXml", StringComparison.Ordinal);

        Assert.True(gate > 0 && refuse > gate, "readiness check must precede the refusal");
        Assert.True(dropAudit > refuse, "the audit option may only be removed after the gate has passed");
        Assert.True(fromAudit > refuse && fromAudit < dropAudit, "enforced policy must be derived from the saved audit XML");
        Assert.True(bootAudit > dropAudit, "Boot Audit on Failure is applied to the enforced policy");
    }

    [Fact]
    public void TheAuditOptionIsRemovedOnlyOnTheEnforcedBranch()
    {
        var s = WdacScript();
        Assert.Equal(1, Regex.Matches(s, @"-Option 3 -Delete").Count);
        Assert.True(s.IndexOf("-Option 3 -Delete", StringComparison.Ordinal) > s.IndexOf("# ---- Enforced:", StringComparison.Ordinal));
    }

    [Fact]
    public void RollbackNotesAreWrittenBeforeTheOperatorIsToldHowToDeploy()
    {
        var s = WdacScript();
        Assert.True(s.IndexOf("ROLLBACK.txt", StringComparison.Ordinal) < s.LastIndexOf("Deploy with:", StringComparison.Ordinal));
    }

    [Fact]
    public void TheDefaultModeIsAudit()
    {
        Parser.ParseFile(RepoPaths.Combine("deploy", "setup-wdac.ps1"), out _, out _);
        Assert.Contains("[ValidateSet('Audit', 'Enforced')] [string] $Mode = 'Audit'", WdacScript());
    }
}
