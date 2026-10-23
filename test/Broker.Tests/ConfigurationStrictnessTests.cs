using Broker.Transport;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Broker.Tests;

public class ConfigReaderTests
{
    private static IConfiguration Cfg(string? value, string key = "K") =>
        new ConfigurationBuilder().AddInMemoryCollection(value is null ? new Dictionary<string, string?>() : new() { [key] = value }).Build();

    [Fact]
    public void AnAbsentKeyUsesTheDocumentedDefault()
    {
        Assert.Equal(7, ConfigReader.Int(Cfg(null), "K", 7));
        Assert.True(ConfigReader.Bool(Cfg(null), "K", true));
    }

    [Theory]
    [InlineData("5", 5)]
    [InlineData("1", 1)]
    [InlineData("100", 100)]
    public void AValidIntegerIsRead(string raw, int expected) =>
        Assert.Equal(expected, ConfigReader.Int(Cfg(raw), "K", 9, min: 1, max: 100));

    [Theory]
    [InlineData("")]
    [InlineData("abc")]
    [InlineData(" 5")]
    [InlineData("5 ")]
    [InlineData("5.0")]
    [InlineData("1e1")]
    [InlineData("+5")]
    [InlineData("99999999999")]
    [InlineData("0")]          // below the minimum
    [InlineData("-1")]
    [InlineData("101")]        // above the maximum
    public void AnythingElseStopsStartupInsteadOfFallingBackToTheDefault(string raw)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => ConfigReader.Int(Cfg(raw, "Pipe:MaxInstances"), "Pipe:MaxInstances", 9, min: 1, max: 100));

        Assert.Contains("Pipe:MaxInstances", ex.Message);
        if (raw.Length > 2) Assert.DoesNotContain(raw, ex.Message);   // the message names the key, not the value
    }

    [Theory]
    [InlineData("true", true)]
    [InlineData("false", false)]
    [InlineData("True", true)]
    [InlineData("FALSE", false)]
    public void AValidBooleanIsRead(string raw, bool expected) =>
        Assert.Equal(expected, ConfigReader.Bool(Cfg(raw), "K", !expected));

    [Theory]
    [InlineData("yes")]
    [InlineData("1")]
    [InlineData("")]
    [InlineData(" true")]
    [InlineData("on")]
    public void AnInvalidBooleanStopsStartupInsteadOfBecomingFalse(string raw)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => ConfigReader.Bool(Cfg(raw, "Elicitation:RequireDistinctApprover"), "Elicitation:RequireDistinctApprover", true));
        Assert.Contains("Elicitation:RequireDistinctApprover", ex.Message);
    }
}

public class ServerConfigurationValidationTests
{
    private static NamedPipeServer Server(Dictionary<string, string?> values)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(values).Build();
        return new NamedPipeServer(new PipeSecurityFactory(config, NullLogger<PipeSecurityFactory>.Instance),
            new RecordingDispatcher(), new ElicitationRouter(NullLogger<ElicitationRouter>.Instance), config, NullLogger<NamedPipeServer>.Instance);
    }

    private static ApprovalPipeServer Approval(Dictionary<string, string?> values)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(values).Build();
        return new ApprovalPipeServer(new PipeSecurityFactory(config, NullLogger<PipeSecurityFactory>.Instance),
            new ElicitationRouter(NullLogger<ElicitationRouter>.Instance), config, NullLogger<ApprovalPipeServer>.Instance);
    }

    [Fact]
    public void DefaultsAreValid()
    {
        Server(new()).ValidateConfiguration();
        Approval(new()).ValidateConfiguration();
    }

    [Theory]
    [InlineData("Pipe:MaxInstances", "abc")]
    [InlineData("Pipe:MaxInstances", "0")]
    [InlineData("Pipe:MaxInstances", "255")]            // the OS allows at most 254 instances
    [InlineData("Pipe:FrameTimeoutSeconds", "0")]
    [InlineData("Pipe:FrameTimeoutSeconds", "five")]
    [InlineData("Pipe:WriteTimeoutSeconds", "-3")]
    [InlineData("Pipe:MaxInFlightPerConnection", "many")]
    [InlineData("Pipe:MaxMalformedRequests", "0")]
    [InlineData("Pipe:MaxConnectionsPerCaller", "0")]
    [InlineData("Elicitation:TtlSeconds", "soon")]
    [InlineData("Elicitation:TtlSeconds", "0")]
    [InlineData("Elicitation:RequireDistinctApprover", "maybe")]
    public void AnInvalidPipeSettingStopsTheServerBeforeItListens(string key, string value)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => Server(new() { [key] = value }).ValidateConfiguration());
        Assert.Contains(key, ex.Message);
    }

    [Theory]
    [InlineData("Elicitation:ApprovalPipeInstances", "x")]
    [InlineData("Elicitation:ApprovalPipeInstances", "0")]
    [InlineData("Elicitation:ApprovalPipeInstances", "300")]
    public void AnInvalidApprovalPipeSettingStopsTheServerBeforeItListens(string key, string value)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => Approval(new() { [key] = value }).ValidateConfiguration());
        Assert.Contains(key, ex.Message);
    }

    [Fact]
    public async Task RunAsyncRefusesToStartWithAnInvalidSetting()
    {
        var server = Server(new() { ["Pipe:MaxInstances"] = "lots", ["Pipe:AllowedSids:0"] = "S-1-5-21-1-2-3-1001" });
        await Assert.ThrowsAsync<InvalidOperationException>(() => server.RunAsync(CancellationToken.None));
    }
}
