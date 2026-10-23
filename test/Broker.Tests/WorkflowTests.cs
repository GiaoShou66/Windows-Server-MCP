using Broker.Core;
using Xunit;

namespace Broker.Tests;

public sealed class WorkflowTests
{
    [Fact]
    public void AdRiskReportUsesConfiguredGroupsAndReturnsOnlyDisabledAccounts()
    {
        var accounts = new[]
        {
            new AdAccountSnapshot("z-user", "Disabled privileged", false,
                new HashSet<string>(new[] { "Domain Admins", "Users" }, StringComparer.OrdinalIgnoreCase)),
            new AdAccountSnapshot("a-user", "Enabled privileged", true,
                new HashSet<string>(new[] { "Domain Admins" }, StringComparer.OrdinalIgnoreCase)),
            new AdAccountSnapshot("b-user", "Disabled ordinary", false,
                new HashSet<string>(new[] { "Users" }, StringComparer.OrdinalIgnoreCase))
        };

        var result = AdRiskAnalyzer.FindDisabledPrivilegedAccounts(
            accounts, new[] { "domain admins" });

        var finding = Assert.Single(result);
        Assert.Equal("z-user", finding.SamAccountName);
        Assert.Equal(new[] { "Domain Admins" }, finding.PrivilegedGroups);
    }

    [Fact]
    public void HealthReportMarksMissingAndPartialServersAsIncomplete()
    {
        var observations = new[]
        {
            new HealthObservation("server-b", "IIS", "Stopped", "site unavailable"),
            new HealthObservation("server-a", "DNS", "Healthy", null, false)
        };

        var report = HealthReportAggregator.Aggregate(
            observations, new[] { "server-a", "server-b", "server-c" });

        Assert.Equal(new[] { "server-a", "server-c" }, report.IncompleteServers);
        Assert.Equal("server-a", report.Observations[0].ServerName);
    }

    [Fact]
    public void PolicyDiffReportsMissingAndDifferentSettingsButNotEqualSettings()
    {
        var snapshots = new[]
        {
            new PolicySnapshot("server-a", new Dictionary<string, string>
            {
                ["Firewall.DefaultInbound"] = "Block",
                ["Audit.Logon"] = "Success"
            }),
            new PolicySnapshot("server-b", new Dictionary<string, string>
            {
                ["Firewall.DefaultInbound"] = "Allow"
            })
        };

        var differences = PolicyDiffAnalyzer.Compare(snapshots);

        Assert.Equal(new[] { "Audit.Logon", "Firewall.DefaultInbound" },
            differences.Select(difference => difference.Setting));
        Assert.Equal("Allow", differences[1].ValuesByServer["server-b"]);
    }
}
