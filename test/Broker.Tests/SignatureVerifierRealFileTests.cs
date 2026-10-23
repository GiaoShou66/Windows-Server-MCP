using System.Diagnostics;
using Broker.Registry;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Broker.Tests;

/// <summary>Captures formatted log messages for test assertions / diagnostics.</summary>
file sealed class CapturingLogger<T> : ILogger<T>
{
    public List<string> Messages { get; } = new();
    public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;
    public bool IsEnabled(LogLevel logLevel) => true;
    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
        Func<TState, Exception?, string> formatter)
        => Messages.Add($"[{logLevel}] {formatter(state, exception)}" + (exception is null ? "" : $" :: {exception}"));

    private sealed class NullScope : IDisposable
    {
        public static readonly NullScope Instance = new();
        public void Dispose() { }
    }
}

/// <summary>
/// Proves the WinVerifyTrust P/Invoke in SignatureVerifier actually works against a real
/// Authenticode-signed file on this machine — not just that it compiles. notepad.exe is
/// signed on every stock Windows install, so this runs without any test fixture setup.
///
/// The expected thumbprint is read via an independent oracle — a `Get-AuthenticodeSignature`
/// PowerShell subprocess — rather than .NET's X509Certificate.CreateFromSignedFile. That API
/// only reads an *embedded* signature, and modern Windows system binaries (including
/// notepad.exe) are catalog-signed instead: CreateFromSignedFile throws "Cannot find the
/// requested object" on them. WinVerifyTrust checks catalogs too, which is exactly why
/// production code uses it instead of CreateFromSignedFile — this test failure during
/// development independently confirmed that choice was necessary, not just a style preference.
///
/// xunit v2 has no built-in Skip; a missing fixture file makes the test pass vacuously
/// (logged via Assert.True with a message) rather than fail the whole suite on a box
/// where notepad.exe happens to be absent.
/// </summary>
public class SignatureVerifierRealFileTests
{
    private const string SignedSystemFile = @"C:\Windows\System32\notepad.exe";

    /// <summary>
    /// Regression test for a native memory leak: WINTRUST_FILE_INFO and WINTRUST_CATALOG_INFO
    /// each carry LPWStr fields, and Marshal.StructureToPtr allocates a SEPARATE native buffer
    /// per string field. The original cleanup only called FreeHGlobal on the outer struct's
    /// buffer, leaking every nested string allocation — on a path (SignatureVerifier.Verify)
    /// that runs on every single tool call. FreeHGlobal/AllocHGlobal bypass the GC heap
    /// entirely, so GC.Collect() cannot reclaim them; genuine growth shows up in the process's
    /// native memory counters — but PrivateMemorySize64 also includes ordinary managed-heap
    /// growth, which doesn't fully settle even after GC.Collect(), so the tolerance has to sit
    /// above that noise floor rather than at zero.
    ///
    /// Measured empirically by deliberately reverting the fix: ~1KB/call leaked (19.7MB over
    /// 20,000 iterations, ~4m42s) — confirming the bug was real. With the fix applied, 3,000
    /// iterations show ~2MB of growth (mostly the managed-heap noise above, not the fixed
    /// native leak). The tolerance here is set above that observed fixed-case baseline while
    /// staying well below what a full regression would add (~3MB extra on top of baseline at
    /// this iteration count) — loose enough not to be flaky, tight enough to still catch a
    /// gross reintroduction of the leak.
    /// </summary>
    [Fact]
    public void RepeatedCatalogVerificationDoesNotLeakNativeMemory()
    {
        if (!File.Exists(SignedSystemFile)) { Assert.True(true, "fixture file absent on this machine"); return; }

        var verifier = new SignatureVerifier(NullLogger<SignatureVerifier>.Instance);
        var thumbprint = ReadEmbeddedThumbprint(SignedSystemFile);
        var tool = ToolWithThumbprint(SignedSystemFile, thumbprint);

        // Warm up (first call pays one-time JIT/provider-load cost) before the baseline snapshot.
        for (int i = 0; i < 10; i++) verifier.Verify(tool);

        GC.Collect();
        GC.WaitForPendingFinalizers();
        using var proc = Process.GetCurrentProcess();
        proc.Refresh();
        long before = proc.PrivateMemorySize64;

        const int iterations = 3_000;
        for (int i = 0; i < iterations; i++)
        {
            var result = verifier.Verify(tool);
            Assert.True(result, $"verification unexpectedly failed at iteration {i}");
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();
        proc.Refresh();
        long after = proc.PrivateMemorySize64;

        long growthBytes = after - before;
        const long toleranceBytes = (long)(3.5 * 1024 * 1024);
        Assert.True(growthBytes < toleranceBytes,
            $"Private memory grew by {growthBytes:N0} bytes over {iterations} verifications " +
            $"(tolerance {toleranceBytes:N0}) — possible native memory leak in WinTrust marshaling.");
    }

    private static ToolManifest ToolWithThumbprint(string path, string thumbprint) => new()
    {
        ToolId = "real-file-test",
        Server = new ServerRef { Path = path, SignatureThumbprint = thumbprint, ServerId = "s" }
    };

    [Fact]
    public void ValidSignatureWithMatchingThumbprintIsTrusted()
    {
        if (!File.Exists(SignedSystemFile)) { Assert.True(true, "fixture file absent on this machine"); return; }

        var actualThumbprint = ReadEmbeddedThumbprint(SignedSystemFile);
        var logger = new CapturingLogger<SignatureVerifier>();
        var verifier = new SignatureVerifier(logger);

        var result = verifier.Verify(ToolWithThumbprint(SignedSystemFile, actualThumbprint));

        Assert.True(result,
            $"expected={actualThumbprint}; log=[{string.Join(" | ", logger.Messages)}]");
    }

    [Fact]
    public void ValidSignatureWithWrongThumbprintIsRejected()
    {
        if (!File.Exists(SignedSystemFile)) { Assert.True(true, "fixture file absent on this machine"); return; }

        var verifier = new SignatureVerifier(NullLogger<SignatureVerifier>.Instance);
        var wrongThumbprint = new string('F', 40); // well-formed but certainly not notepad's

        var result = verifier.Verify(ToolWithThumbprint(SignedSystemFile, wrongThumbprint));

        Assert.False(result, "A validly signed file with a mismatched expected thumbprint must still be rejected");
    }

    [Fact]
    public void MissingFileIsRejected()
    {
        var verifier = new SignatureVerifier(NullLogger<SignatureVerifier>.Instance);
        var result = verifier.Verify(ToolWithThumbprint(@"C:\does\not\exist.exe", new string('A', 40)));
        Assert.False(result);
    }

    [Fact]
    public void UnsignedFileIsRejected()
    {
        var tempFile = Path.Combine(Path.GetTempPath(), $"mcp-test-unsigned-{Guid.NewGuid():N}.txt");
        File.WriteAllText(tempFile, "not a signed binary");
        try
        {
            var verifier = new SignatureVerifier(NullLogger<SignatureVerifier>.Instance);
            var result = verifier.Verify(ToolWithThumbprint(tempFile, new string('A', 40)));
            Assert.False(result, "WinVerifyTrust has no provider for a plain text file; must fail closed");
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    private static string ReadEmbeddedThumbprint(string path)
    {
        var psi = new ProcessStartInfo("powershell.exe")
        {
            ArgumentList =
            {
                "-NoProfile", "-NonInteractive", "-Command",
                $"(Get-AuthenticodeSignature -LiteralPath '{path.Replace("'", "''")}').SignerCertificate.Thumbprint"
            },
            RedirectStandardOutput = true,
            UseShellExecute = false
        };

        using var proc = Process.Start(psi) ?? throw new InvalidOperationException("Could not start powershell.exe");
        var output = proc.StandardOutput.ReadToEnd().Trim();
        proc.WaitForExit(10_000);

        if (string.IsNullOrWhiteSpace(output))
            throw new InvalidOperationException($"Get-AuthenticodeSignature returned no thumbprint for {path}");

        return output;
    }
}
