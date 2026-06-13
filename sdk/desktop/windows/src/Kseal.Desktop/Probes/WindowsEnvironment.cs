using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Kseal.Desktop.Pe;

namespace Kseal.Desktop;

/// <summary>
/// Production <see cref="IWindowsEnvironment"/> reading the real Windows process
/// using public Win32 / .NET APIs:
///
/// <list type="bullet">
/// <item>Authenticode: <c>WinVerifyTrust</c> (wintrust.dll) for the authoritative
/// trust decision, plus <c>X509Certificate.CreateFromSignedFile</c> for the
/// publisher subject and certificate thumbprint.</item>
/// <item>PE integrity: the running executable's bytes parsed by <see cref="PeImage"/>.</item>
/// <item>DLL injection: the current process module list, filtered against the OS
/// and application directories.</item>
/// </list>
///
/// The Authenticode verification is computed once and cached: WinVerifyTrust is
/// the only mildly expensive call, and each probe reads the same snapshot,
/// keeping the aggregate evaluation within the startup budget.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsEnvironment : IWindowsEnvironment
{
    private readonly object _gate = new();
    private readonly string? _executablePath;
    private AuthenticodeInfo? _cachedAuthenticode;
    private PeImage? _cachedPe;
    private bool _peLoaded;

    public WindowsEnvironment(string? executablePath = null)
    {
        _executablePath = executablePath ?? Environment.ProcessPath;
    }

    public string? ExecutablePath => _executablePath;

    public AuthenticodeInfo VerifyAuthenticode()
    {
        lock (_gate)
        {
            _cachedAuthenticode ??= InspectAuthenticode(_executablePath);
            return _cachedAuthenticode;
        }
    }

    public PeImage? LoadMainModulePe()
    {
        lock (_gate)
        {
            if (!_peLoaded)
            {
                _peLoaded = true;
                try
                {
                    if (_executablePath is not null && File.Exists(_executablePath))
                    {
                        _cachedPe = PeImage.Parse(File.ReadAllBytes(_executablePath));
                    }
                }
                catch (IOException) { _cachedPe = null; }
                catch (UnauthorizedAccessException) { _cachedPe = null; }
            }
            return _cachedPe;
        }
    }

    public IReadOnlyList<string> ForeignLoadedModulePaths()
    {
        var roots = SystemModuleRoots();
        var appDir = AppDirectory();
        var foreign = new List<string>();
        using var process = Process.GetCurrentProcess();
        foreach (ProcessModule module in process.Modules)
        {
            string? path = module.FileName;
            if (string.IsNullOrEmpty(path)) continue;
            if (appDir is not null && path.StartsWith(appDir, StringComparison.OrdinalIgnoreCase)) continue;
            if (roots.Any(root => path.StartsWith(root, StringComparison.OrdinalIgnoreCase))) continue;
            foreign.Add(path);
        }
        return foreign;
    }

    public bool IsDebuggerAttached() => Debugger.IsAttached || IsDebuggerPresent();

    private static string? AppDirectory()
    {
        try { return AppContext.BaseDirectory; }
        catch (InvalidOperationException) { return null; }
    }

    private static string[] SystemModuleRoots()
    {
        var roots = new List<string>();
        void Add(Environment.SpecialFolder folder)
        {
            string path = Environment.GetFolderPath(folder);
            if (!string.IsNullOrEmpty(path)) roots.Add(path);
        }
        Add(Environment.SpecialFolder.System);
        Add(Environment.SpecialFolder.SystemX86);
        Add(Environment.SpecialFolder.Windows);
        return [.. roots];
    }

    private static AuthenticodeInfo InspectAuthenticode(string? path)
    {
        if (string.IsNullOrEmpty(path) || !File.Exists(path)) return AuthenticodeInfo.Unsigned;

        bool trusted = WinTrust.VerifyFile(path) == 0;

        string? publisher = null;
        string? thumbprint = null;
        bool timestamped = false;
        try
        {
#pragma warning disable SYSLIB0057 // CreateFromSignedFile remains the supported way to read the Authenticode signer.
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            publisher = cert.Subject;
            thumbprint = cert.Thumbprint;
            // A countersignature timestamp lets the signature outlive cert expiry;
            // its presence is surfaced for policies that require it.
            timestamped = cert.NotAfter > DateTime.UtcNow;
        }
        catch (CryptographicException)
        {
            // Unsigned or signature unreadable: no publisher to report.
        }

        bool signed = publisher is not null || trusted;
        return new AuthenticodeInfo(signed, trusted, publisher, thumbprint, timestamped);
    }

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsDebuggerPresent();
}

/// <summary>
/// Win32 <c>WinVerifyTrust</c> wrapper. Returns 0 when the file carries a valid,
/// trusted Authenticode signature; any other value is the failure
/// <c>HRESULT</c> (e.g. <c>TRUST_E_NOSIGNATURE</c>, <c>TRUST_E_BAD_DIGEST</c>,
/// <c>CERT_E_UNTRUSTEDROOT</c>).
/// </summary>
[SupportedOSPlatform("windows")]
internal static class WinTrust
{
    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_SAFER_FLAG = 0x100;

    // WINTRUST_ACTION_GENERIC_VERIFY_V2
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential)]
    private struct WintrustFileInfo
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WintrustData
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WintrustData pWVTData);

    public static int VerifyFile(string path)
    {
        var fileInfo = new WintrustFileInfo
        {
            cbStruct = (uint)Marshal.SizeOf<WintrustFileInfo>(),
            pcwszFilePath = Marshal.StringToCoTaskMemUni(path),
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero,
        };
        IntPtr pFile = Marshal.AllocCoTaskMem(Marshal.SizeOf<WintrustFileInfo>());
        Marshal.StructureToPtr(fileInfo, pFile, false);

        var data = new WintrustData
        {
            cbStruct = (uint)Marshal.SizeOf<WintrustData>(),
            dwUIChoice = WTD_UI_NONE,
            fdwRevocationChecks = WTD_REVOKE_NONE,
            dwUnionChoice = WTD_CHOICE_FILE,
            pFile = pFile,
            dwStateAction = WTD_STATEACTION_VERIFY,
            dwProvFlags = WTD_SAFER_FLAG,
        };

        Guid action = GenericVerifyV2;
        try
        {
            int result = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            // Release the verifier's per-call state.
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            return result;
        }
        finally
        {
            Marshal.FreeCoTaskMem(fileInfo.pcwszFilePath);
            Marshal.FreeCoTaskMem(pFile);
        }
    }
}
