using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using Broker.Core;
using Microsoft.Extensions.Logging;

namespace Broker.Registry;

// ---- Manifest POCOs (mirror policy/tool-manifest.schema.json) ----

public sealed class ServerRef
{
    [JsonPropertyName("serverId")] public string ServerId { get; set; } = "";
    [JsonPropertyName("path")] public string Path { get; set; } = "";
    [JsonPropertyName("signatureThumbprint")] public string SignatureThumbprint { get; set; } = "";
    [JsonPropertyName("provenance")] public string Provenance { get; set; } = "unverified";
}

public sealed class ParamRange
{
    [JsonPropertyName("min")] public double Min { get; set; }
    [JsonPropertyName("max")] public double Max { get; set; }
}

public sealed class ParameterAllowlist
{
    [JsonPropertyName("enumValues")] public List<string>? EnumValues { get; set; }
    [JsonPropertyName("regexPattern")] public string? RegexPattern { get; set; }
    [JsonPropertyName("maxLength")] public int? MaxLength { get; set; }
    [JsonPropertyName("range")] public ParamRange? Range { get; set; }
}

public sealed class ToolParameter
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("type")] public string Type { get; set; } = "string";
    [JsonPropertyName("required")] public bool Required { get; set; }
    [JsonPropertyName("allowlist")] public ParameterAllowlist Allowlist { get; set; } = new();
}

public sealed class JeaMapping
{
    [JsonPropertyName("endpointName")] public string EndpointName { get; set; } = "";
    [JsonPropertyName("roleCapabilityName")] public string RoleCapabilityName { get; set; } = "";
    [JsonPropertyName("cmdlet")] public string Cmdlet { get; set; } = "";
    [JsonPropertyName("moduleName")] public string ModuleName { get; set; } = "";
    [JsonPropertyName("accessGroup")] public string AccessGroup { get; set; } = "";
    [JsonPropertyName("useGmsa")] public bool UseGmsa { get; set; }
    [JsonPropertyName("gmsaAccount")] public string? GmsaAccount { get; set; }
    [JsonPropertyName("virtualAccountGroups")] public List<string>? VirtualAccountGroups { get; set; }
    [JsonPropertyName("externalCommands")] public List<string>? ExternalCommands { get; set; }
}

public sealed class ToolManifest
{
    [JsonPropertyName("toolId")] public string ToolId { get; set; } = "";
    [JsonPropertyName("displayName")] public string DisplayName { get; set; } = "";
    [JsonPropertyName("description")] public string Description { get; set; } = "";
    [JsonPropertyName("server")] public ServerRef Server { get; set; } = new();
    [JsonPropertyName("riskTier")] public string RiskTierRaw { get; set; } = "read";
    [JsonPropertyName("requiresElicitation")] public bool? RequiresElicitation { get; set; }
    [JsonPropertyName("jeaMapping")] public JeaMapping JeaMapping { get; set; } = new();
    [JsonPropertyName("parameters")] public List<ToolParameter> Parameters { get; set; } = new();
    [JsonPropertyName("untrustedInputSources")] public List<string> UntrustedInputSources { get; set; } = new();
    [JsonPropertyName("maskedFields")] public List<string> MaskedFields { get; set; } = new();
    [JsonPropertyName("revoked")] public bool Revoked { get; set; }

    [JsonIgnore]
    public RiskTier RiskTier => RiskTierRaw.ToLowerInvariant() switch
    {
        "write" => Core.RiskTier.Write,
        "destructive" => Core.RiskTier.Destructive,
        _ => Core.RiskTier.Read
    };

    [JsonIgnore]
    public bool ElicitationRequired =>
        RequiresElicitation ?? RiskTier is Core.RiskTier.Write or Core.RiskTier.Destructive;
}

public sealed class ManifestFile
{
    [JsonPropertyName("tools")] public List<ToolManifest> Tools { get; set; } = new();
}

/// <summary>
/// Loads and hot-reloads the local tool registry. Revocation is fast (file watch,
/// no restart); adding a tool is deliberate (restart required) — asymmetry is intentional.
/// </summary>
public sealed class ManifestStore : IDisposable
{
    private readonly string _path;
    private readonly ILogger<ManifestStore> _logger;
    private readonly FileSystemWatcher _watcher;
    private readonly object _lock = new();
    private readonly object _reloadLock = new();
    private Dictionary<string, ToolManifest> _tools = new();

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip
    };

    public event Action<IReadOnlyCollection<string>>? ToolsRevoked;

    public ManifestStore(string path, ILogger<ManifestStore> logger)
    {
        _path = path;
        _logger = logger;
        Load();

        var dir = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(path))!;
        var file = System.IO.Path.GetFileName(path);
        _watcher = new FileSystemWatcher(dir, file) { NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName };
        _watcher.Changed += (_, _) => Reload();
        _watcher.Created += (_, _) => Reload();
        _watcher.EnableRaisingEvents = true;
    }

    public IReadOnlyCollection<ToolManifest> All
    {
        get { lock (_lock) return _tools.Values.ToArray(); }
    }

    public ToolManifest? Get(string toolId)
    {
        lock (_lock) return _tools.TryGetValue(toolId, out var m) && !m.Revoked ? m : null;
    }

    private void Load()
    {
        if (!File.Exists(_path))
        {
            _logger.LogWarning("Manifest not found at {Path}; registry is empty", _path);
            lock (_lock) _tools = new();
            return;
        }

        var json = File.ReadAllText(_path);
        var parsed = JsonSerializer.Deserialize<ManifestFile>(json, JsonOpts) ?? new ManifestFile();
        lock (_lock) _tools = parsed.Tools.ToDictionary(t => t.ToolId, StringComparer.Ordinal);
        _logger.LogInformation("Loaded {Count} tools from manifest", _tools.Count);
    }

    // FileSystemWatcher can deliver Changed/Created on multiple threadpool threads concurrently.
    // Without serializing here, two overlapping saves could each snapshot a stale "before" set
    // and race on Load(), producing an incorrect ToolsRevoked diff — on the exact path meant to
    // be the fast security kill-switch. The lock makes rapid-fire edits process strictly in order.
    private void Reload()
    {
        lock (_reloadLock)
        {
        try
        {
            var before = new HashSet<string>(ActiveToolIds());
            // small debounce; editors write in bursts
            Thread.Sleep(150);
            Load();
            var after = new HashSet<string>(ActiveToolIds());

            before.ExceptWith(after);
            if (before.Count > 0)
            {
                _logger.LogWarning("Tools revoked on reload: {Tools}", string.Join(", ", before));
                ToolsRevoked?.Invoke(before);
            }
        }
        catch (Exception ex)
        {
            // fail closed: on parse error keep the last good set, do not widen access
            _logger.LogError(ex, "Manifest reload failed; keeping previous registry");
        }
        }
    }

    private IEnumerable<string> ActiveToolIds()
    {
        lock (_lock) return _tools.Values.Where(t => !t.Revoked).Select(t => t.ToolId).ToArray();
    }

    public void Dispose() => _watcher.Dispose();
}

/// <summary>
/// Re-verifies a server file's Authenticode signature at call time, not just at registration.
/// Uses WinVerifyTrust, which validates the file hash against the embedded signature (so a
/// tampered binary carrying a copied signature fails) and builds the cert chain to a trusted
/// root. Works for both PE images and PowerShell script modules (.psm1) via the registered
/// subject interface package. The signer leaf thumbprint is then cross-checked against the
/// manifest so swapping to a different (but validly signed) file is also rejected.
/// </summary>
public interface ISignatureVerifier
{
    bool Verify(ToolManifest tool);
}

public sealed class SignatureVerifier : ISignatureVerifier
{
    private readonly ILogger<SignatureVerifier> _logger;

    public SignatureVerifier(ILogger<SignatureVerifier> logger) => _logger = logger;

    public bool Verify(ToolManifest tool)
    {
        var path = tool.Server.Path;
        if (!File.Exists(path))
        {
            _logger.LogWarning("Server file missing: {Path}", path);
            return false;
        }

        var expected = tool.Server.SignatureThumbprint.Replace(" ", "");

        try
        {
            var (trusted, thumbprint, hr, win32Error) = WinTrust.VerifyAndGetThumbprint(path);
            if (!trusted)
            {
                _logger.LogWarning("WinVerifyTrust failed for {Tool} ({Path}): hr=0x{Hr:X8} win32Error={Win32}",
                    tool.ToolId, path, hr, win32Error);
                return false;
            }

            if (!string.Equals(thumbprint, expected, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("Thumbprint mismatch for {Tool}: expected {Exp} got {Act}",
                    tool.ToolId, expected, thumbprint);
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Signature check threw for {Tool}; treating as unverified", tool.ToolId);
            return false;
        }
    }
}

/// <summary>
/// WinVerifyTrust interop: trusts a file's signature (hash + chain) and recovers the
/// signer leaf certificate thumbprint from the retained provider state.
///
/// A plain WTD_CHOICE_FILE verify only checks an *embedded* Authenticode signature.
/// Most Windows system binaries (and some vendor-deployed packages) are catalog-signed
/// instead — WinVerifyTrust returns TRUST_E_NOSIGNATURE for those even though a tool
/// like Get-AuthenticodeSignature reports them as validly signed. VerifyAndGetThumbprint
/// therefore falls back to an explicit CryptCATAdmin catalog lookup (WTD_CHOICE_CATALOG)
/// whenever the embedded check specifically fails with TRUST_E_NOSIGNATURE, so a
/// catalog-signed server is not incorrectly rejected.
/// </summary>
internal static class WinTrust
{
    private static Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_CHOICE_CATALOG = 2;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;

    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 0x1;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x80;

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        [MarshalAs(UnmanagedType.LPWStr)] public string? pcwszCatalogFilePath;
        [MarshalAs(UnmanagedType.LPWStr)] public string? pcwszMemberTag;
        [MarshalAs(UnmanagedType.LPWStr)] public string? pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile; // also serves as pCatalog for WTD_CHOICE_CATALOG
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CATALOG_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFile;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CRYPT_PROVIDER_CERT
    {
        public uint cbStruct;
        public IntPtr pCert; // PCCERT_CONTEXT
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, IntPtr pWVTData);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr WTHelperProvDataFromStateData(IntPtr hStateData);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr WTHelperGetProvSignerFromChain(
        IntPtr pProvData, uint idxSigner, [MarshalAs(UnmanagedType.Bool)] bool fCounterSigner, uint idxCounterSigner);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr WTHelperGetProvCertFromChain(IntPtr pSgnr, uint idxCert);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminAcquireContext2(
        out IntPtr catAdmin, IntPtr subsystem, string hashAlgorithm, IntPtr strongHashPolicy, uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(
        IntPtr catAdmin, IntPtr hFile, ref uint hashSize, IntPtr hash, uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(
        IntPtr catAdmin, IntPtr hash, uint hashSize, uint flags, ref IntPtr prevCatInfo);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATCatalogInfoFromContext(
        IntPtr catInfo, ref CATALOG_INFO catalogInfo, uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr catAdmin, IntPtr catInfo, uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr catAdmin, uint flags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileW(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes,
        uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    public static (bool trusted, string thumbprint, int hr, int win32Error) VerifyAndGetThumbprint(string filePath)
    {
        var embedded = VerifyEmbedded(filePath);
        if (embedded.trusted || embedded.hr != TRUST_E_NOSIGNATURE)
            return embedded;

        // No embedded signature — this is the expected shape for a catalog-signed file
        // (most Windows system binaries). Fall back to an explicit catalog lookup.
        return VerifyCatalog(filePath);
    }

    private static (bool trusted, string thumbprint, int hr, int win32Error) VerifyEmbedded(string filePath)
    {
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = filePath,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero
        };

        IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        Marshal.StructureToPtr(fileInfo, pFile, false);

        var data = new WINTRUST_DATA
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
            dwUIChoice = WTD_UI_NONE,
            fdwRevocationChecks = WTD_REVOKE_NONE,
            dwUnionChoice = WTD_CHOICE_FILE,
            pFile = pFile,
            dwStateAction = WTD_STATEACTION_VERIFY,
            dwProvFlags = 0
        };

        IntPtr pData = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
        Marshal.StructureToPtr(data, pData, false);

        try
        {
            int result = WinVerifyTrust(IntPtr.Zero, ref WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);
            if (result != 0)
                return (false, string.Empty, result, Marshal.GetLastWin32Error());

            var verified = Marshal.PtrToStructure<WINTRUST_DATA>(pData);
            string thumbprint = ExtractThumbprint(verified.hWVTStateData);
            return (true, thumbprint, 0, 0);
        }
        finally
        {
            CloseState(pData);
            Marshal.FreeHGlobal(pData);
            // StructureToPtr for a struct with an LPWStr field allocates a SEPARATE native
            // buffer for that string; FreeHGlobal only frees the struct's own block, not the
            // nested string allocation. DestroyStructure walks the marshaled fields and frees
            // those too — must run before FreeHGlobal, since it reads the struct's contents
            // to know which pointers to release.
            Marshal.DestroyStructure<WINTRUST_FILE_INFO>(pFile);
            Marshal.FreeHGlobal(pFile);
        }
    }

    private static (bool trusted, string thumbprint, int hr, int win32Error) VerifyCatalog(string filePath)
    {
        IntPtr hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, IntPtr.Zero,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        if (hFile == IntPtr.Zero || hFile == new IntPtr(-1))
            return (false, string.Empty, 0, Marshal.GetLastWin32Error());

        IntPtr catAdmin = IntPtr.Zero;
        IntPtr catInfo = IntPtr.Zero;
        IntPtr hashBuf = IntPtr.Zero;
        IntPtr pCatalogInfo = IntPtr.Zero;
        IntPtr pData = IntPtr.Zero;

        try
        {
            if (!CryptCATAdminAcquireContext2(out catAdmin, IntPtr.Zero, "SHA256", IntPtr.Zero, 0))
                return (false, string.Empty, 0, Marshal.GetLastWin32Error());

            uint hashSize = 0;
            CryptCATAdminCalcHashFromFileHandle2(catAdmin, hFile, ref hashSize, IntPtr.Zero, 0);
            if (hashSize == 0)
                return (false, string.Empty, 0, Marshal.GetLastWin32Error());

            hashBuf = Marshal.AllocHGlobal((int)hashSize);
            if (!CryptCATAdminCalcHashFromFileHandle2(catAdmin, hFile, ref hashSize, hashBuf, 0))
                return (false, string.Empty, 0, Marshal.GetLastWin32Error());

            IntPtr prevCatInfo = IntPtr.Zero;
            catInfo = CryptCATAdminEnumCatalogFromHash(catAdmin, hashBuf, hashSize, 0, ref prevCatInfo);
            if (catInfo == IntPtr.Zero)
                return (false, string.Empty, TRUST_E_NOSIGNATURE, Marshal.GetLastWin32Error());

            var catalogInfo = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>(), wszCatalogFile = "" };
            if (!CryptCATCatalogInfoFromContext(catInfo, ref catalogInfo, 0))
                return (false, string.Empty, 0, Marshal.GetLastWin32Error());

            var hashHex = Convert.ToHexString(ReadBytes(hashBuf, (int)hashSize));

            var wtCatalog = new WINTRUST_CATALOG_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
                dwCatalogVersion = 0,
                pcwszCatalogFilePath = catalogInfo.wszCatalogFile,
                pcwszMemberTag = hashHex,
                pcwszMemberFilePath = filePath,
                hMemberFile = hFile,
                pbCalculatedFileHash = hashBuf,
                cbCalculatedFileHash = hashSize,
                pcCatalogContext = IntPtr.Zero,
                hCatAdmin = catAdmin
            };

            pCatalogInfo = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
            Marshal.StructureToPtr(wtCatalog, pCatalogInfo, false);

            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_CATALOG,
                pFile = pCatalogInfo,
                dwStateAction = WTD_STATEACTION_VERIFY,
                dwProvFlags = 0
            };

            pData = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
            Marshal.StructureToPtr(data, pData, false);

            int result = WinVerifyTrust(IntPtr.Zero, ref WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);
            if (result != 0)
                return (false, string.Empty, result, Marshal.GetLastWin32Error());

            var verified = Marshal.PtrToStructure<WINTRUST_DATA>(pData);
            string thumbprint = ExtractThumbprint(verified.hWVTStateData);
            return (true, thumbprint, 0, 0);
        }
        finally
        {
            if (pData != IntPtr.Zero) { CloseState(pData); Marshal.FreeHGlobal(pData); }
            // WINTRUST_CATALOG_INFO has three LPWStr fields (catalog path, member tag, member
            // file path) — StructureToPtr allocated a separate native buffer for each. Same
            // leak class as VerifyEmbedded's WINTRUST_FILE_INFO; DestroyStructure must run
            // before FreeHGlobal for the same reason.
            if (pCatalogInfo != IntPtr.Zero)
            {
                Marshal.DestroyStructure<WINTRUST_CATALOG_INFO>(pCatalogInfo);
                Marshal.FreeHGlobal(pCatalogInfo);
            }
            if (hashBuf != IntPtr.Zero) Marshal.FreeHGlobal(hashBuf);
            if (catInfo != IntPtr.Zero) CryptCATAdminReleaseCatalogContext(catAdmin, catInfo, 0);
            if (catAdmin != IntPtr.Zero) CryptCATAdminReleaseContext(catAdmin, 0);
            CloseHandle(hFile);
        }
    }

    private static void CloseState(IntPtr pData)
    {
        var closeData = Marshal.PtrToStructure<WINTRUST_DATA>(pData);
        closeData.dwStateAction = WTD_STATEACTION_CLOSE;
        Marshal.StructureToPtr(closeData, pData, false);
        WinVerifyTrust(IntPtr.Zero, ref WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);
    }

    private static byte[] ReadBytes(IntPtr ptr, int length)
    {
        var buf = new byte[length];
        Marshal.Copy(ptr, buf, 0, length);
        return buf;
    }

    private static string ExtractThumbprint(IntPtr hStateData)
    {
        if (hStateData == IntPtr.Zero) return string.Empty;

        IntPtr provData = WTHelperProvDataFromStateData(hStateData);
        if (provData == IntPtr.Zero) return string.Empty;

        IntPtr sgnr = WTHelperGetProvSignerFromChain(provData, 0, false, 0);
        if (sgnr == IntPtr.Zero) return string.Empty;

        IntPtr provCert = WTHelperGetProvCertFromChain(sgnr, 0);
        if (provCert == IntPtr.Zero) return string.Empty;

        var cpc = Marshal.PtrToStructure<CRYPT_PROVIDER_CERT>(provCert);
        if (cpc.pCert == IntPtr.Zero) return string.Empty;

        using var cert = new X509Certificate2(cpc.pCert);
        return cert.Thumbprint ?? string.Empty;
    }
}
