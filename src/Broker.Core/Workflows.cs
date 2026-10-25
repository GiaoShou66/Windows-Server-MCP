using System.Text.Json.Serialization;

namespace Broker.Core;

public sealed record AdAccountSnapshot(
    string SamAccountName,
    string DisplayName,
    bool Enabled,
    IReadOnlySet<string> GroupNames);

public sealed record AdRiskFinding(
    string SamAccountName,
    string DisplayName,
    IReadOnlyList<string> PrivilegedGroups);

public static class AdRiskAnalyzer
{
    public static IReadOnlyList<AdRiskFinding> FindDisabledPrivilegedAccounts(
        IEnumerable<AdAccountSnapshot> accounts,
        IEnumerable<string> privilegedGroups)
    {
        ArgumentNullException.ThrowIfNull(accounts);
        ArgumentNullException.ThrowIfNull(privilegedGroups);

        var groups = privilegedGroups
            .Where(static group => !string.IsNullOrWhiteSpace(group))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        return accounts
            .Where(account => !account.Enabled)
            .Select(account => new AdRiskFinding(
                account.SamAccountName,
                account.DisplayName,
                account.GroupNames
                    .Where(groups.Contains)
                    .Order(StringComparer.OrdinalIgnoreCase)
                    .ToArray()))
            .Where(static finding => finding.PrivilegedGroups.Count > 0)
            .OrderBy(static finding => finding.SamAccountName, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }
}

public sealed record HealthObservation(
    string ServerName,
    string Component,
    string Status,
    string? Detail,
    bool IsComplete = true);

public sealed record ServerHealthReport(
    IReadOnlyList<HealthObservation> Observations,
    IReadOnlyList<string> IncompleteServers);

public static class HealthReportAggregator
{
    public static ServerHealthReport Aggregate(
        IEnumerable<HealthObservation> observations,
        IEnumerable<string> expectedServers)
    {
        ArgumentNullException.ThrowIfNull(observations);
        ArgumentNullException.ThrowIfNull(expectedServers);

        var result = observations
            .OrderBy(observation => observation.ServerName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(observation => observation.Component, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var observedServers = result
            .Select(observation => observation.ServerName)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var incomplete = expectedServers
            .Where(server => !string.IsNullOrWhiteSpace(server))
            .Where(server => !observedServers.Contains(server) ||
                result.Any(observation =>
                    string.Equals(observation.ServerName, server, StringComparison.OrdinalIgnoreCase) &&
                    !observation.IsComplete))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new ServerHealthReport(result, incomplete);
    }
}

public sealed record PolicySnapshot(
    string ServerName,
    IReadOnlyDictionary<string, string> Settings);

public sealed record PolicyDifference(
    string Setting,
    IReadOnlyDictionary<string, string> ValuesByServer);

public static class PolicyDiffAnalyzer
{
    public static IReadOnlyList<PolicyDifference> Compare(
        IEnumerable<PolicySnapshot> snapshots)
    {
        ArgumentNullException.ThrowIfNull(snapshots);

        var inputs = snapshots
            .Where(snapshot => !string.IsNullOrWhiteSpace(snapshot.ServerName))
            .GroupBy(snapshot => snapshot.ServerName, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.Last())
            .ToArray();
        var settings = inputs
            .SelectMany(snapshot => snapshot.Settings.Keys)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase);

        return settings
            .Select(setting =>
            {
                var values = inputs
                    .Where(snapshot => snapshot.Settings.ContainsKey(setting))
                    .ToDictionary(
                        snapshot => snapshot.ServerName,
                        snapshot => snapshot.Settings[setting],
                        StringComparer.OrdinalIgnoreCase);
                return new PolicyDifference(setting, values);
            })
            .Where(difference => difference.ValuesByServer.Values
                .Distinct(StringComparer.Ordinal)
                .Count() > 1 ||
                difference.ValuesByServer.Count != inputs.Length)
            .ToArray();
    }
}
