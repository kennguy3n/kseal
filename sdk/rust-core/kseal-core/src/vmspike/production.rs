//! Bounded production path for selective virtualization candidates.
//!
//! This module is still gated behind the default-off `vm-spike` cargo feature,
//! but unlike the original spike-only toy routine it models the shippable path:
//! a closed allow-list of cold, non-crypto glue routines can be lowered through
//! the maintained IR compiler, encoded with the per-build seed, and paired with
//! an encrypted, build-bound retrace map. Anything outside that allow-list is
//! rejected before code generation.

use super::ir::{self, Expr};
use super::retrace::{build_hash_from_seed, encrypt_map};
use super::{decode_with_seed, encode_with_seed, interp, BuildSeed, Program};

/// Routines that may be virtualized by the production path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Candidate {
    /// Proof-signing assembly glue: canonical ordering/domain separation around
    /// proof material, not HMAC/Ed25519/SHA math.
    ProofSigningAssembly,
    /// Kill-switch verification glue: scoped decision/wrapper logic, not the
    /// signed-config signature primitive.
    KillSwitchVerifyGlue,
    /// Attestation-token assembly: nonce/claim marshalling, not attestation
    /// verification or cryptographic proof.
    AttestationTokenAssembly,
}

impl Candidate {
    /// Stable routine name recorded in bytecode/retrace artifacts.
    #[must_use]
    pub fn routine(self) -> &'static str {
        match self {
            Candidate::ProofSigningAssembly => "proof_signing_assembly",
            Candidate::KillSwitchVerifyGlue => "kill_switch_verify_glue",
            Candidate::AttestationTokenAssembly => "attestation_token_assembly",
        }
    }

    /// Number of 64-bit words consumed by the candidate's glue expression.
    #[must_use]
    pub fn inputs(self) -> u8 {
        match self {
            Candidate::ProofSigningAssembly => 4,
            Candidate::KillSwitchVerifyGlue | Candidate::AttestationTokenAssembly => 3,
        }
    }

    fn expr(self) -> Expr {
        match self {
            Candidate::ProofSigningAssembly => proof_signing_assembly_expr(),
            Candidate::KillSwitchVerifyGlue => kill_switch_verify_glue_expr(),
            Candidate::AttestationTokenAssembly => attestation_token_assembly_expr(),
        }
    }

    /// Native reference for parity testing and for non-virtualized execution.
    #[must_use]
    pub fn native(self, words: &[u64]) -> u64 {
        match self {
            Candidate::ProofSigningAssembly => proof_signing_assembly_native(
                words.first().copied().unwrap_or(0),
                words.get(1).copied().unwrap_or(0),
                words.get(2).copied().unwrap_or(0),
                words.get(3).copied().unwrap_or(0),
            ),
            Candidate::KillSwitchVerifyGlue => kill_switch_verify_glue_native(
                words.first().copied().unwrap_or(0),
                words.get(1).copied().unwrap_or(0),
                words.get(2).copied().unwrap_or(0),
            ),
            Candidate::AttestationTokenAssembly => attestation_token_assembly_native(
                words.first().copied().unwrap_or(0),
                words.get(1).copied().unwrap_or(0),
                words.get(2).copied().unwrap_or(0),
            ),
        }
    }
}

/// Explicit rejection classes for targets that must never be virtualized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectedTarget {
    /// Hot path such as risk scoring, event ingest/serialization, or transport.
    HotPath,
    /// Golden-vector cryptographic primitive or proof output.
    GoldenVectorCrypto,
    /// Whole-program/class/application virtualization request.
    WholeProgram,
    /// Unknown target name.
    Unknown,
}

/// Error returned before code generation when a target is not eligible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionError {
    /// The requested target is explicitly disallowed.
    Rejected(RejectedTarget),
    /// The IR compiler rejected an allow-listed candidate.
    Lower(ir::LowerError),
}

impl From<ir::LowerError> for SelectionError {
    fn from(value: ir::LowerError) -> Self {
        SelectionError::Lower(value)
    }
}

/// Shippable virtualization artifacts for one candidate.
#[derive(Debug, Clone)]
pub struct CandidateArtifacts {
    /// Candidate that was lowered.
    pub candidate: Candidate,
    /// Per-build encoded bytecode to link into a HIGH-strength build.
    pub bytecode: Vec<u8>,
    /// Private encrypted VM-pc → source-site map for crash triage.
    pub retrace_map: Vec<u8>,
    /// Build hash binding for the retrace map.
    pub build_hash: [u8; 32],
}

/// A decoded candidate program, ready to run without per-call decoding cost.
#[derive(Debug, Clone)]
pub struct VirtualCandidate {
    candidate: Candidate,
    program: Program,
}

impl VirtualCandidate {
    /// Builds and decodes the candidate once for a per-build seed.
    ///
    /// # Errors
    /// Returns a compiler/selection error if the candidate ever stops fitting
    /// the bounded VM constraints.
    pub fn build(candidate: Candidate, seed: &BuildSeed) -> Result<Self, SelectionError> {
        let lowered = lower_candidate(candidate)?;
        let bytes = encode_with_seed(&lowered.program, seed);
        let program = decode_with_seed(&bytes, seed).expect("freshly encoded candidate decodes");
        Ok(Self { candidate, program })
    }

    /// Runs the decoded virtualized candidate.
    ///
    /// # Errors
    /// Returns a VM fault if the caller supplies fewer words than the candidate
    /// declares. Well-formed build-plugin glue passes exactly `candidate.inputs()`.
    pub fn run(&self, words: &[u64]) -> Result<u64, interp::VmError> {
        debug_assert_eq!(words.len(), usize::from(self.candidate.inputs()));
        interp::run_ir(&self.program, words)
    }
}

/// Resolves a user/plugin target name to an allow-listed candidate.
///
/// # Errors
/// Rejects hot paths, golden-vector crypto, whole-program virtualization, and
/// unknown names before any lowering or artifact generation.
pub fn select_candidate(target: &str) -> Result<Candidate, SelectionError> {
    let normalized = target.trim().to_ascii_lowercase().replace(['-', '.'], "_");
    match normalized.as_str() {
        "proof_signing_assembly" | "proof_signing_glue" => Ok(Candidate::ProofSigningAssembly),
        "kill_switch_verify_glue" | "kill_switch_verify_gate" => {
            Ok(Candidate::KillSwitchVerifyGlue)
        }
        "attestation_token_assembly" | "attestation_claim_assembly" => {
            Ok(Candidate::AttestationTokenAssembly)
        }
        "risk_scoring" | "event_ingest" | "event_serialization" | "transport" => {
            Err(SelectionError::Rejected(RejectedTarget::HotPath))
        }
        "verify_ed25519"
        | "hmac_sha256"
        | "sha256"
        | "generate_request_proof"
        | "kill_switch_preimage"
        | "signed_config_signature" => {
            Err(SelectionError::Rejected(RejectedTarget::GoldenVectorCrypto))
        }
        "whole_program" | "whole_app" | "all" | "*" => {
            Err(SelectionError::Rejected(RejectedTarget::WholeProgram))
        }
        _ => Err(SelectionError::Rejected(RejectedTarget::Unknown)),
    }
}

/// Builds bytecode and encrypted retrace artifacts for a selected candidate.
///
/// # Errors
/// Returns if the target is not allow-listed or if lowering fails.
pub fn build_candidate_artifacts(
    target: &str,
    seed: &BuildSeed,
) -> Result<CandidateArtifacts, SelectionError> {
    let candidate = select_candidate(target)?;
    let lowered = lower_candidate(candidate)?;
    let build_hash = build_hash_from_seed(seed);
    Ok(CandidateArtifacts {
        candidate,
        bytecode: encode_with_seed(&lowered.program, seed),
        retrace_map: encrypt_map(&lowered.retrace, seed, &build_hash, candidate.routine()),
        build_hash,
    })
}

fn lower_candidate(candidate: Candidate) -> Result<super::LoweredProgram, SelectionError> {
    Ok(ir::lower(
        candidate.routine(),
        candidate.inputs(),
        &candidate.expr(),
    )?)
}

#[must_use]
fn proof_signing_assembly_native(
    method: u64,
    path_hash: u64,
    body_hash: u64,
    nonce_hi: u64,
) -> u64 {
    let mut acc = method.rotate_left(7) ^ path_hash;
    acc = acc.wrapping_add(0xD6E8_FEB8_6659_FD93);
    acc ^= body_hash.rotate_right(11);
    acc = acc.wrapping_mul(0x9E37_79B1_85EB_CA87);
    acc ^ nonce_hi.rotate_left(23)
}

fn proof_signing_assembly_expr() -> Expr {
    use Expr::{Add, Const, Input, Mul, Rotl, Rotr, Xor};
    let acc = Xor(Expr::bx(Rotl(Expr::bx(Input(0)), 7)), Expr::bx(Input(1)));
    let acc = Add(Expr::bx(acc), Expr::bx(Const(0xD6E8_FEB8_6659_FD93)));
    let acc = Xor(Expr::bx(acc), Expr::bx(Rotr(Expr::bx(Input(2)), 11)));
    let acc = Mul(Expr::bx(acc), Expr::bx(Const(0x9E37_79B1_85EB_CA87)));
    Xor(Expr::bx(acc), Expr::bx(Rotl(Expr::bx(Input(3)), 23)))
}

#[must_use]
fn kill_switch_verify_glue_native(scope_hash: u64, command: u64, version: u64) -> u64 {
    let mut acc = scope_hash ^ command.wrapping_mul(0xA24B_AED4_963E_E407);
    acc = acc.rotate_left(17);
    acc = acc.wrapping_add(version ^ 0x94D0_49BB_1331_11EB);
    acc ^ (acc >> 31)
}

fn kill_switch_verify_glue_expr() -> Expr {
    use Expr::{Add, Const, Input, Mul, Rotl, Shr, Xor};
    let cmd = Mul(Expr::bx(Input(1)), Expr::bx(Const(0xA24B_AED4_963E_E407)));
    let acc = Xor(Expr::bx(Input(0)), Expr::bx(cmd));
    let acc = Rotl(Expr::bx(acc), 17);
    let ver = Xor(Expr::bx(Input(2)), Expr::bx(Const(0x94D0_49BB_1331_11EB)));
    let acc = Add(Expr::bx(acc), Expr::bx(ver));
    Xor(Expr::bx(acc.clone()), Expr::bx(Shr(Expr::bx(acc), 31)))
}

#[must_use]
fn attestation_token_assembly_native(nonce_lo: u64, claims_hash: u64, build_hash_lo: u64) -> u64 {
    let mut acc = nonce_lo.wrapping_add(claims_hash.rotate_left(29));
    acc ^= build_hash_lo.rotate_right(19);
    acc = acc.wrapping_mul(0xC2B2_AE3D_27D4_EB4F);
    acc ^ (acc >> 33)
}

fn attestation_token_assembly_expr() -> Expr {
    use Expr::{Add, Const, Input, Mul, Rotl, Rotr, Shr, Xor};
    let acc = Add(Expr::bx(Input(0)), Expr::bx(Rotl(Expr::bx(Input(1)), 29)));
    let acc = Xor(Expr::bx(acc), Expr::bx(Rotr(Expr::bx(Input(2)), 19)));
    let acc = Mul(Expr::bx(acc), Expr::bx(Const(0xC2B2_AE3D_27D4_EB4F)));
    Xor(Expr::bx(acc.clone()), Expr::bx(Shr(Expr::bx(acc), 33)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vmspike::retrace::Symbolicator;

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
    }

    #[test]
    fn allow_list_accepts_only_cold_non_crypto_glue() {
        assert_eq!(
            select_candidate("proof-signing-glue").unwrap(),
            Candidate::ProofSigningAssembly
        );
        assert_eq!(
            select_candidate("kill_switch_verify_gate").unwrap(),
            Candidate::KillSwitchVerifyGlue
        );
        assert_eq!(
            select_candidate("attestation.token.assembly").unwrap(),
            Candidate::AttestationTokenAssembly
        );
        assert_eq!(
            select_candidate("risk_scoring").unwrap_err(),
            SelectionError::Rejected(RejectedTarget::HotPath)
        );
        assert_eq!(
            select_candidate("hmac_sha256").unwrap_err(),
            SelectionError::Rejected(RejectedTarget::GoldenVectorCrypto)
        );
        assert_eq!(
            select_candidate("whole_program").unwrap_err(),
            SelectionError::Rejected(RejectedTarget::WholeProgram)
        );
    }

    #[test]
    fn candidates_match_native_over_random_inputs() {
        let seed = BuildSeed::from_u64(0xC0DE_CAFE);
        let mut rng = Rng(0xA11C_E123);
        for candidate in [
            Candidate::ProofSigningAssembly,
            Candidate::KillSwitchVerifyGlue,
            Candidate::AttestationTokenAssembly,
        ] {
            let vm = VirtualCandidate::build(candidate, &seed).unwrap();
            for _ in 0..5000 {
                let words: Vec<u64> = (0..candidate.inputs()).map(|_| rng.next()).collect();
                assert_eq!(
                    vm.run(&words).unwrap(),
                    candidate.native(&words),
                    "{candidate:?}"
                );
            }
        }
    }

    #[test]
    fn artifacts_are_polymorphic_and_retrace_maps_are_private() {
        let a = BuildSeed::from_u64(0xAAAA_0001);
        let b = BuildSeed::from_u64(0xBBBB_0002);
        let art_a = build_candidate_artifacts("proof_signing_assembly", &a).unwrap();
        let art_b = build_candidate_artifacts("proof_signing_assembly", &b).unwrap();
        assert_ne!(art_a.bytecode, art_b.bytecode);
        assert_ne!(art_a.retrace_map, art_b.retrace_map);

        let sym = Symbolicator::open(
            &art_a.retrace_map,
            &a,
            &art_a.build_hash,
            art_a.candidate.routine(),
        )
        .expect("candidate retrace opens with matching key");
        assert!(sym
            .resolve(crate::vmspike::VmFrame { pc: 0 })
            .expect("pc 0 resolves")
            .function
            .contains("proof_signing"));
        assert!(Symbolicator::open(
            &art_a.retrace_map,
            &b,
            &art_a.build_hash,
            art_a.candidate.routine()
        )
        .is_err());
    }
}
