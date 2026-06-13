namespace Kseal.Desktop;

/// <summary>
/// Expected-integrity baseline for the protected Windows app, supplied by the
/// integrator / signed config. A disabled check or an empty/null expectation
/// contributes no signal, so an unconfigured baseline never raises a false
/// positive.
/// </summary>
public sealed record WindowsIntegrityPolicy
{
    /// <summary>Legitimate Authenticode publisher (certificate subject). Null disables the check.</summary>
    public string? ExpectedPublisher { get; init; }

    /// <summary>Legitimate signing-certificate SHA-1/SHA-256 thumbprint. Null disables the check.</summary>
    public string? ExpectedCertificateThumbprint { get; init; }

    /// <summary>When true, an unsigned or invalid Authenticode signature raises a signal.</summary>
    public bool RequireValidSignature { get; init; } = true;

    /// <summary>When true, a signature lacking a valid trusted timestamp raises a signal.</summary>
    public bool RequireTimestamp { get; init; }

    /// <summary>
    /// Expected lowercase-hex SHA-256 of the named PE section's raw bytes. When
    /// set, a mismatch raises an in-file tamper signal. Null disables the check.
    /// </summary>
    public string? ExpectedSectionSha256 { get; init; }

    /// <summary>The PE section the <see cref="ExpectedSectionSha256"/> baseline covers (default <c>.text</c>).</summary>
    public string SectionName { get; init; } = ".text";
}
