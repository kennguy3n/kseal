using Kseal.Desktop.Pe;

namespace Kseal.Desktop;

/// <summary>
/// Result of inspecting the running executable's Authenticode signature.
/// Coarse, non-PII facts only — never raw certificate bytes.
/// </summary>
public sealed record AuthenticodeInfo(
    bool IsSigned,
    bool SignatureValid,
    string? Publisher,
    string? CertificateThumbprint,
    bool TimestampValid)
{
    /// <summary>An unsigned binary.</summary>
    public static readonly AuthenticodeInfo Unsigned = new(false, false, null, null, false);
}

/// <summary>
/// Narrow seam over the Windows code-integrity surface the probes inspect.
///
/// Probes depend on this interface rather than the Win32 APIs directly so they
/// stay deterministic and unit-testable on any host (a fake supplies controlled
/// inputs) while the production <c>WindowsEnvironment</c> reads the real
/// process. This is also the <b>mock boundary for the external OS attestation
/// calls</b>: the production implementation issues the real <c>WinVerifyTrust</c>
/// query; tests substitute a fake. None of these methods perform network I/O.
/// </summary>
public interface IWindowsEnvironment
{
    /// <summary>Verifies the running executable's Authenticode signature (WinVerifyTrust).</summary>
    AuthenticodeInfo VerifyAuthenticode();

    /// <summary>Parses the running executable's PE image, or null when unavailable.</summary>
    PeImage? LoadMainModulePe();

    /// <summary>
    /// Paths of loaded modules that are not part of the application directory or
    /// the OS (System32 / WinSxS) — candidate injected DLLs.
    /// </summary>
    IReadOnlyList<string> ForeignLoadedModulePaths();

    /// <summary>Whether a debugger is attached to the process.</summary>
    bool IsDebuggerAttached();

    /// <summary>The running executable's full path, when available.</summary>
    string? ExecutablePath { get; }
}
