namespace Kseal.Desktop;

/// <summary>Coarse confidence in a signal or decision. Mirrors <c>kseal.v1.Confidence</c>.</summary>
public enum Confidence
{
    Unspecified = 0,
    Low = 1,
    Medium = 2,
    High = 3,
}

/// <summary>Fused trust classification. Mirrors <c>kseal.v1.TrustLevel</c>.</summary>
public enum TrustLevel
{
    Unspecified = 0,
    Trusted = 1,
    LowRisk = 2,
    MediumRisk = 3,
    HighRisk = 4,
    Critical = 5,
}

/// <summary>Telemetry event categories. Mirrors <c>kseal.v1.EventType</c>.</summary>
public enum EventType
{
    Unspecified = 0,
    RuntimeTamper = 1,
    Debugger = 2,
    RootRisk = 3,
    AttestationFail = 4,
    NetworkMitm = 5,
    PolicyDecision = 6,
    HookingDetected = 7,
    AppIntegrityFail = 8,
    EnvironmentRisk = 9,
}

/// <summary>
/// Reporting platform. Mirrors <c>kseal.v1.Platform</c>, which currently defines
/// only UNSPECIFIED/ANDROID/IOS. Desktop builds report <see cref="Unspecified"/>
/// (the safe, forward-compatible default) until a desktop discriminant is added
/// server-side. See docs/desktop-sdk.md.
/// </summary>
public enum Platform
{
    Unspecified = 0,
    Android = 1,
    Ios = 2,
}

/// <summary>Result of an on-device risk evaluation.</summary>
public sealed record RiskAssessment(
    ulong RiskBits,
    IReadOnlySet<RiskSignal> Signals,
    uint Score,
    Confidence Confidence,
    TrustLevel TrustLevel)
{
    /// <summary>Whether no risk signals were observed.</summary>
    public bool IsClean => RiskBits == 0;
}

/// <summary>Per-request proof binding a request to the current trust token.</summary>
public sealed record RequestProof(
    string TokenId,
    byte[] RequestHash,
    byte[] Nonce,
    long Sequence,
    byte[] ProofBytes);
