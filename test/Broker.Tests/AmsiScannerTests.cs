using System.Text;
using Broker.Policy;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Broker.Tests;

internal sealed class FakeAmsiApi : IAmsiApi
{
    public Func<int>? InitializeResult { get; set; }
    public Exception? InitializeThrows { get; set; }
    public int OpenSessionHr { get; set; }
    public int ScanHr { get; set; }
    public Exception? ScanThrows { get; set; }
    public int ScanResult { get; set; } = 1; // AMSI_RESULT_NOT_DETECTED

    public int InitializeCalls, ScanCalls, CloseCalls, UninitializeCalls;
    public string? LastScanned;

    public int Initialize(string appName, out IntPtr context)
    {
        Interlocked.Increment(ref InitializeCalls);
        if (InitializeThrows is not null) throw InitializeThrows;
        context = new IntPtr(1);
        return InitializeResult?.Invoke() ?? 0;
    }

    public int OpenSession(IntPtr context, out IntPtr session) { session = new IntPtr(2); return OpenSessionHr; }

    public int Scan(IntPtr context, byte[] buffer, uint length, string contentName, IntPtr session, out int result)
    {
        Interlocked.Increment(ref ScanCalls);
        LastScanned = Encoding.Unicode.GetString(buffer);
        if (ScanThrows is not null) throw ScanThrows;
        result = ScanResult;
        return ScanHr;
    }

    public void CloseSession(IntPtr context, IntPtr session) => Interlocked.Increment(ref CloseCalls);
    public void Uninitialize(IntPtr context) => Interlocked.Increment(ref UninitializeCalls);
}

public class AmsiScannerTests
{
    private static readonly Dictionary<string, string> Args = new() { ["Name"] = "value" };

    private static AmsiScanner Scanner(FakeAmsiApi api, AmsiMode mode) =>
        new(NullLogger<AmsiScanner>.Instance, mode, api);

    [Fact]
    public void CleanContentIsAllowed()
    {
        var api = new FakeAmsiApi();
        var d = Scanner(api, AmsiMode.BestEffort).Scan("c", Args);
        Assert.True(d.Allowed);
        Assert.Equal(1, api.ScanCalls);
        Assert.Contains("value", api.LastScanned);
    }

    [Theory]
    [InlineData(32768)]   // AMSI_RESULT_DETECTED
    [InlineData(40000)]
    [InlineData(int.MaxValue)]
    public void DetectedContentIsDeniedInBothModes(int result)
    {
        foreach (var mode in new[] { AmsiMode.BestEffort, AmsiMode.Strict })
        {
            var d = Scanner(new FakeAmsiApi { ScanResult = result }, mode).Scan("c", Args);
            Assert.False(d.Allowed);
            Assert.Equal("amsi-detected-malicious-content", d.Reason);
        }
    }

    [Theory]
    [InlineData(0x4000)]  // AMSI_RESULT_BLOCKED_BY_ADMIN_START
    [InlineData(0x4FFF)]  // AMSI_RESULT_BLOCKED_BY_ADMIN_END
    public void BlockedByAdminIsDenied(int result)
    {
        var d = Scanner(new FakeAmsiApi { ScanResult = result }, AmsiMode.BestEffort).Scan("c", Args);
        Assert.False(d.Allowed);
        Assert.Equal("amsi-blocked-by-admin", d.Reason);
    }

    [Theory]
    [InlineData(0)]       // CLEAN
    [InlineData(1)]       // NOT_DETECTED
    [InlineData(0x3FFF)]
    [InlineData(0x5000)]  // outside both the admin-block range and the detected range
    public void NonMalwareResultsAreAllowed(int result)
    {
        Assert.True(Scanner(new FakeAmsiApi { ScanResult = result }, AmsiMode.Strict).Scan("c", Args).Allowed);
    }

    [Fact]
    public void NothingIsScannedWhenThereAreNoParameters()
    {
        var api = new FakeAmsiApi();
        Assert.True(Scanner(api, AmsiMode.Strict).Scan("c", new Dictionary<string, string>()).Allowed);
        Assert.Equal(0, api.InitializeCalls);
        Assert.Equal(0, api.ScanCalls);
    }

    [Fact]
    public void InitializationFailureIsBestEffortAllowButStrictDeny()
    {
        var best = Scanner(new FakeAmsiApi { InitializeResult = () => unchecked((int)0x80070057) }, AmsiMode.BestEffort).Scan("c", Args);
        var strict = Scanner(new FakeAmsiApi { InitializeResult = () => unchecked((int)0x80070057) }, AmsiMode.Strict).Scan("c", Args);

        Assert.True(best.Allowed);
        Assert.False(strict.Allowed);
        Assert.Equal("amsi-unavailable", strict.Reason);
    }

    [Fact]
    public void MissingAmsiLibraryNeverEscapesAsAnException()
    {
        var thrower = new DllNotFoundException("amsi.dll");

        var best = Scanner(new FakeAmsiApi { InitializeThrows = thrower }, AmsiMode.BestEffort).Scan("c", Args);
        var strict = Scanner(new FakeAmsiApi { InitializeThrows = thrower }, AmsiMode.Strict).Scan("c", Args);

        Assert.True(best.Allowed);
        Assert.False(strict.Allowed);
        Assert.Equal("amsi-unavailable", strict.Reason);
    }

    [Fact]
    public void ScanFailureIsBestEffortAllowButStrictDeny()
    {
        var best = Scanner(new FakeAmsiApi { ScanHr = -1 }, AmsiMode.BestEffort).Scan("c", Args);
        var strict = Scanner(new FakeAmsiApi { ScanHr = -1 }, AmsiMode.Strict).Scan("c", Args);

        Assert.True(best.Allowed);
        Assert.False(strict.Allowed);
        Assert.Equal("amsi-scan-failed", strict.Reason);
    }

    [Fact]
    public void ScanExceptionIsBestEffortAllowButStrictDeny()
    {
        var best = Scanner(new FakeAmsiApi { ScanThrows = new InvalidOperationException("boom") }, AmsiMode.BestEffort).Scan("c", Args);
        var strict = Scanner(new FakeAmsiApi { ScanThrows = new InvalidOperationException("boom") }, AmsiMode.Strict).Scan("c", Args);

        Assert.True(best.Allowed);
        Assert.Equal("amsi-scan-failed", strict.Reason);
    }

    [Fact]
    public void FailedInitializationIsRememberedAndNotRetriedOnEveryCall()
    {
        var api = new FakeAmsiApi { InitializeResult = () => -1 };
        var scanner = Scanner(api, AmsiMode.BestEffort);
        for (int i = 0; i < 5; i++) scanner.Scan("c", Args);
        Assert.Equal(1, api.InitializeCalls);
    }

    [Fact]
    public void SessionOpenFailureStillScansWithoutASession()
    {
        var api = new FakeAmsiApi { OpenSessionHr = -1, ScanResult = 32768 };
        var d = Scanner(api, AmsiMode.BestEffort).Scan("c", Args);
        Assert.False(d.Allowed);
        Assert.Equal(1, api.ScanCalls);
    }

    [Fact]
    public void DisposeReleasesNativeResourcesExactlyOnce()
    {
        var api = new FakeAmsiApi();
        var scanner = Scanner(api, AmsiMode.BestEffort);
        scanner.Scan("c", Args);
        scanner.Dispose();
        scanner.Dispose();
        Assert.Equal(1, api.CloseCalls);
        Assert.Equal(1, api.UninitializeCalls);
    }

    [Fact]
    public void DefaultModeIsBestEffortSoExistingDeploymentsKeepTheirBehaviour()
    {
        var api = new FakeAmsiApi { InitializeResult = () => -1 };
        var scanner = new AmsiScanner(NullLogger<AmsiScanner>.Instance, api);
        Assert.True(scanner.Scan("c", Args).Allowed);
    }

    [Theory]
    [InlineData("BestEffort", AmsiMode.BestEffort)]
    [InlineData("strict", AmsiMode.Strict)]
    [InlineData("STRICT", AmsiMode.Strict)]
    public void ModeParsesFromConfiguration(string raw, AmsiMode expected) =>
        Assert.Equal(expected, AmsiOptions.ParseMode(raw));

    [Theory]
    [InlineData("")]
    [InlineData("Off")]
    [InlineData("strictt")]
    public void UnrecognizedModeStopsStartupInsteadOfSilentlyDefaulting(string raw) =>
        Assert.Throws<InvalidOperationException>(() => AmsiOptions.ParseMode(raw));

    [Fact]
    public void ScanWithTheRealApiNeverThrowsWhateverTheHost()
    {
        // Real P/Invoke path: amsi.dll is absent off Windows and may lack a provider on Windows.
        // Either way the scanner must return a decision, never throw.
        using var scanner = new AmsiScanner(NullLogger<AmsiScanner>.Instance);
        Assert.NotNull(scanner.Scan("c", Args));
    }

    [WindowsOnlyFact]
    public void RealAmsiOnWindowsAcceptsABenignParameterSet()
    {
        using var scanner = new AmsiScanner(NullLogger<AmsiScanner>.Instance);
        Assert.True(scanner.Scan("c", new Dictionary<string, string> { ["ServiceName"] = "Spooler" }).Allowed);
    }
}
