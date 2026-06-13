namespace Kseal.Desktop;

/// <summary>A minted trust session returned by <c>VerifyAttestation</c>.</summary>
public sealed record TrustSession(
    string TokenId,
    byte[] SignedToken,
    bool Accepted,
    string RejectionReason,
    long ExpiresAt,
    TrustLevel RiskLevel,
    IReadOnlyList<string> CapabilityScopes);

/// <summary>The server's decision after validating a per-request proof. Mirrors <c>RequestProofResult.Decision</c>.</summary>
public enum TrustDecision
{
    Unspecified = 0,
    Allow = 1,
    StepUp = 2,
    Deny = 3,
}

/// <summary>Outcome of validating a request proof.</summary>
public sealed record RequestProofDecision(TrustDecision Decision, string Reason);

/// <summary>Errors surfaced by the trust-session transport.</summary>
public sealed class TrustSessionException(string message) : Exception(message);

/// <summary>
/// Drives the device-plane trust flow against the existing <c>TrustService</c>
/// RPCs (<c>GetNonce</c> → <c>VerifyAttestation</c> → <c>ValidateRequestProof</c>).
/// Never invoked at launch — the host calls it explicitly to establish or
/// refresh a session, satisfying the no-launch-network budget.
/// </summary>
public interface ITrustSessionClient
{
    /// <summary>Requests a fresh single-use challenge nonce.</summary>
    byte[] GetNonce();

    /// <summary>Submits the fused risk state + platform attestation and returns the minted session.</summary>
    TrustSession VerifyAttestation(
        byte[] nonce, ulong riskBitset, string buildHash, string policyHash, string instanceId, byte[] attestationToken);

    /// <summary>Asks the server to validate a per-request proof and return its decision.</summary>
    RequestProofDecision ValidateRequestProof(RequestProof proof);
}
