package io.kseal.gradle.tasks

import io.kseal.gradle.internal.Crypto
import io.kseal.gradle.internal.Json
import io.kseal.gradle.internal.ObfuscationStrength
import java.io.File
import org.gradle.api.DefaultTask
import org.gradle.api.InvalidUserDataException
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.CacheableTask
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction

/**
 * Emits the private retrace artifact for selective Rust-core virtualization.
 *
 * The task is deliberately closed-world: only documented cold, non-crypto glue
 * candidates are accepted, and candidates are legal only at
 * [ObfuscationStrength.HIGH]. The output is deterministic for the same seed and
 * candidate set, cacheable, and private/out-of-band: the sealed retrace payload
 * goes under build/kseal/private rather than app assets.
 */
@CacheableTask
abstract class GenerateVirtualizationArtifactsTask : DefaultTask() {

    @get:Input
    abstract val strength: Property<String>

    @get:Input
    abstract val candidates: ListProperty<String>

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val seedFile: RegularFileProperty

    @get:OutputFile
    abstract val retraceMapFile: RegularFileProperty

    @get:OutputFile
    abstract val reportFile: RegularFileProperty

    @TaskAction
    fun generate() {
        val parsedStrength = parseStrength()
        val selected = normalizeCandidates(candidates.getOrElse(emptyList()))
        if (selected.isEmpty()) {
            writeReport(status = "skipped", selected = emptyList(), retraceSha = "", plaintextSha = "")
            retraceMapFile.get().asFile.delete()
            return
        }
        if (parsedStrength != ObfuscationStrength.HIGH) {
            throw InvalidUserDataException(
                "kseal: selective virtualization requires obfuscation.strength=high; got ${parsedStrength.name.lowercase()}",
            )
        }

        val seed = Crypto.unhex(seedFile.get().asFile.readText().trim())
        require(seed.size == Crypto.SEED_BYTES) { "polymorphism seed must be ${Crypto.SEED_BYTES} bytes" }
        val plaintext = Json.write(
            linkedMapOf<String, Any?>(
                "schema" to "kseal.vm-retrace/v1",
                "candidates" to selected.map { it.external },
                "routines" to selected.map { it.routine },
                "guardrails" to listOf("cold", "non_crypto", "no_hot_paths", "no_whole_program"),
            ),
            indent = false,
        ).toByteArray()
        val key = Crypto.deriveKey(seed, "selective-virtualization/retrace")
        val sealed = Crypto.seal(key, plaintext, "vm-retrace:${selected.joinToString(",") { it.routine }}")
        val opened = try {
            Crypto.open(key, sealed)
        } catch (e: RuntimeException) {
            throw InvalidUserDataException("kseal: selective virtualization retrace self-check failed", e)
        }
        if (!opened.contentEquals(plaintext)) {
            throw InvalidUserDataException("kseal: selective virtualization retrace round-trip mismatch")
        }
        writeBytes(retraceMapFile.get().asFile, sealed)
        writeReport(status = "applied", selected = selected, retraceSha = Crypto.sha256Hex(sealed), plaintextSha = Crypto.sha256Hex(plaintext))
    }

    private fun parseStrength(): ObfuscationStrength = try {
        ObfuscationStrength.parseStrict(strength.getOrElse("off"))
    } catch (e: IllegalArgumentException) {
        throw InvalidUserDataException("kseal: ${e.message}", e)
    }

    private fun writeReport(status: String, selected: List<VirtualizationCandidate>, retraceSha: String, plaintextSha: String) {
        val report = linkedMapOf<String, Any?>(
            "transform" to "selective-virtualization",
            "status" to status,
            "strength" to parseStrength().name.lowercase(),
            "candidates" to selected.map { it.external },
            "routines" to selected.map { it.routine },
            "retrace_map" to if (retraceSha.isBlank()) null else mapOf(
                "path" to "private/vm-retrace.map",
                "sha256" to retraceSha,
                "plaintext_sha256" to plaintextSha,
                "encrypted" to true,
                "round_trip_verified" to true,
            ),
        )
        writeText(reportFile.get().asFile, Json.write(report))
    }

    private fun normalizeCandidates(raw: List<String>): List<VirtualizationCandidate> {
        val out = linkedMapOf<String, VirtualizationCandidate>()
        for (name in raw) {
            val normalized = name.trim().lowercase().replace('-', '_').replace('.', '_')
            if (normalized.isBlank()) continue
            val candidate = allowedCandidates[normalized]
                ?: rejectCandidate(normalized)
            out[candidate.routine] = candidate
        }
        return out.values.toList()
    }

    private fun rejectCandidate(name: String): Nothing {
        val reason = when (name) {
            "risk_scoring", "event_ingest", "event_serialization", "transport" -> "hot path"
            "verify_ed25519", "hmac_sha256", "sha256", "generate_request_proof",
            "kill_switch_preimage", "signed_config_signature",
            -> "golden-vector crypto"
            "whole_program", "whole_app", "all", "*" -> "whole-program virtualization"
            else -> "unknown target"
        }
        throw InvalidUserDataException("kseal: refusing to virtualize '$name' ($reason)")
    }

    private fun writeBytes(file: File, bytes: ByteArray) {
        file.parentFile?.mkdirs()
        file.writeBytes(bytes)
    }

    private fun writeText(file: File, text: String) {
        file.parentFile?.mkdirs()
        file.writeText(text)
    }

    private data class VirtualizationCandidate(val external: String, val routine: String)

    private companion object {
        val allowedCandidates: Map<String, VirtualizationCandidate> = listOf(
            VirtualizationCandidate("proof_signing_assembly", "proof_signing_assembly"),
            VirtualizationCandidate("proof_signing_glue", "proof_signing_assembly"),
            VirtualizationCandidate("kill_switch_verify_glue", "kill_switch_verify_glue"),
            VirtualizationCandidate("kill_switch_verify_gate", "kill_switch_verify_glue"),
            VirtualizationCandidate("attestation_token_assembly", "attestation_token_assembly"),
            VirtualizationCandidate("attestation_claim_assembly", "attestation_token_assembly"),
        ).associateBy { it.external }
    }
}
