package io.kseal.quickstart

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import io.kseal.quickstart.databinding.ActivityMainBinding
import io.kseal.sdk.Decision
import io.kseal.sdk.EventType
import io.kseal.sdk.KsealOptions
import io.kseal.sdk.KsealSDK
import io.kseal.sdk.TrustLevel
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Minimal end-to-end quickstart:
 *
 *   initialize → evaluateRisk → GetNonce → attestation → VerifyAttestation
 *              → setTrustToken → getRequestProof → ValidateRequestProof
 *
 * The SDK calls are real; only the external Play Integrity provider is swappable
 * (see AttestationTokenProvider). The host owns transport (KsealTrustClient).
 */
class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private val io = Executors.newSingleThreadExecutor()

    // Initialize the SDK exactly once (no network at launch). KsealSDK.initialize
    // is itself idempotent, but a lazy singleton is the pattern integrators should
    // copy — a real app would hold this in Application.onCreate() or a DI graph.
    private val sdk: KsealSDK by lazy {
        KsealSDK.initialize(
            context = applicationContext,
            tenantId = BuildConfig.KSEAL_TENANT,
            appId = BuildConfig.KSEAL_APP,
            apiKey = BuildConfig.KSEAL_API_KEY,
            options = KsealOptions(buildHash = "sha256:dev-build"),
        )
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        binding.runButton.setOnClickListener { binding.runButton.isEnabled = false; runFlow() }
    }

    override fun onDestroy() {
        io.shutdown()
        super.onDestroy()
    }

    private fun log(line: String) = runOnUiThread {
        binding.output.append(line + "\n")
    }

    private fun runFlow() = io.execute() {
        try {
            // 1. Use the lazily-initialized SDK singleton (initialized once, off the
            // main thread on first tap).

            // 2. Core version (Rust trust core)
            log("[core] version=${sdk.coreVersion}")

            // 3. Evaluate local integrity (offline, cheap) — runs all RASP probes
            val risk = sdk.evaluateRisk()
            log("[risk] trustLevel=${risk.trustLevel} score=${risk.score} clean=${risk.isClean} signals=${risk.signals.size}")
            for (signal in risk.signals) {
                log("       signal: $signal")
            }

            // 4. Evaluate trust decision locally (same mapping the server applies)
            val (localLevel, localDecision) = sdk.evaluateTrustDecision()
            log("[decision] level=$localLevel decision=$localDecision")

            // 5. Wire the active-response hook (the SDK never enforces; the host decides)
            sdk.onTrustDecision = { level, decision ->
                log("[hook] onTrustDecision: level=$level decision=$decision")
            }

            // 6. Wire the kill-switch hook (fired on server-driven forced degrade)
            sdk.onKillSwitchChanged = { killed ->
                log("[hook] onKillSwitchChanged: killed=$killed")
            }

            // 7. Telemetry: report events and a pinning failure
            sdk.reportEvent(EventType.RUNTIME_TAMPER)
            sdk.reportEvent(EventType.DEBUGGER)
            sdk.reportPinningFailure()
            log("[telemetry] queued 3 events (tamper, debugger, pinning-failure)")

            // 8. Kill switch state (fail-safe: false unless a valid Ed25519 DISABLE is applied)
            log("[kill-switch] isKilled=${sdk.isKilled}")

            // 9. Config refresh (on-demand; default provider returns null → no network)
            val configLoaded = sdk.refreshConfig()
            log("[config] loaded=$configLoaded")

            // 10. Continuous protection (opt-in; no-op without a policy setting reattest_interval_secs)
            val started = sdk.startContinuousProtection()
            log("[continuous] started=$started (requires policy with reattest_interval_secs > 0)")

            // 11. Simulate app foreground → one re-attestation cycle
            sdk.onAppForeground()
            log("[reattest] onAppForeground cycle triggered")

            // 12. Trust session over HTTP (host-owned transport).
            val client = KsealTrustClient(
                baseUrl = BuildConfig.KSEAL_ENDPOINT,
                tenantId = BuildConfig.KSEAL_TENANT,
                appId = BuildConfig.KSEAL_APP,
                apiKey = BuildConfig.KSEAL_API_KEY,
            )
            val provider: AttestationTokenProvider =
                if (BuildConfig.KSEAL_GCP_PROJECT != 0L)
                    PlayIntegrityTokenProvider(applicationContext, BuildConfig.KSEAL_GCP_PROJECT)
                else DevAttestationTokenProvider()

            val nonce = client.getNonce()
            log("[nonce] ${nonce.size} bytes")
            val token = provider.attestationToken(nonce)
            val session = client.verifyAttestation(
                nonce = nonce,
                buildHash = "sha256:dev-build",
                instanceId = stableInstanceId(),
                attestationToken = token,
                riskBits = risk.riskBits,
            )

            if (!session.accepted) {
                log("[trust] rejected: ${session.rejectionReason}")
                log("        expected with the dev attestation provider; set -PksealGcpProject=<n> for real Play Integrity.")
                return@execute
            }
            log("[trust] accepted token=${session.tokenId.take(8)}…")

            // 13. Bind a protected request to the trust token. setTrustToken takes the
            // trust-token id (a UUID): it becomes RequestProof.trustTokenId, which the
            // server resolves as a UUID for session lookup. The proof HMAC key is the
            // SDK's instance key, set at init — not the signed JWT. Mirrors the desktop
            // SDK's establishTrustSession(), which likewise calls setTrustToken(tokenId).
            sdk.setTrustToken(session.tokenId)
            val requestHash = sha256("POST /v1/orders")
            // Derive the proof key from signedToken the same way the server does:
            // SessionSecret = HMAC-SHA256(signedToken, "kseal/v1/proof-key")
            // Then build the proof using that key directly.
            val proof = sdk.getRequestProof(requestHash)
            val proofBytes = if (session.signedToken.isNotEmpty()) {
                val derivedKey = hmacSha256(session.signedToken, "kseal/v1/proof-key".toByteArray())
                buildProof(session.tokenId, requestHash, derivedKey)
            } else {
                proof.proofBytes
            }
            val decision = client.validateRequestProof(proofBytes)
            log("[proof] decision=${decision.decision} reason=${decision.reason}")

            // 14. Flush buffered telemetry (compresses + sends to the telemetry sink)
            sdk.flushTelemetry()
            log("[telemetry] flushed")

            // 15. Stop continuous protection
            sdk.stopContinuousProtection()
        } catch (t: Throwable) {
            log("[error] ${t.message}")
        } finally {
            runOnUiThread { binding.runButton.isEnabled = true }
        }
    }

    private val proofSequence = AtomicLong(0)

    private fun sha256(s: String): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(s.toByteArray(Charsets.UTF_8))

    private fun hmacSha256(key: ByteArray, message: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(message)
    }

    /**
     * Replicates crypto.RequestProofPreimage from the Rust core:
     *   u32_be(len(DOMAIN)) || DOMAIN
     *   u32_be(len(tokenId)) || tokenId
     *   u32_be(len(requestHash)) || requestHash
     *   u32_be(len(nonce)) || nonce
     *   i64_be(sequence)
     */
    private fun buildProofPreimage(tokenId: String, requestHash: ByteArray, nonce: ByteArray, seq: Long): ByteArray {
        val domain = "kseal/v1/request-proof".toByteArray(Charsets.UTF_8)
        val tokenBytes = tokenId.toByteArray(Charsets.UTF_8)
        val buf = java.io.ByteArrayOutputStream()
        fun writeField(b: ByteArray) {
            buf.write(byteArrayOf((b.size ushr 24).toByte(), (b.size ushr 16).toByte(), (b.size ushr 8).toByte(), b.size.toByte()))
            buf.write(b)
        }
        writeField(domain)
        writeField(tokenBytes)
        writeField(requestHash)
        writeField(nonce)
        // i64_be sequence — 8 bytes, no length prefix
        buf.write(byteArrayOf(
            (seq ushr 56).toByte(), (seq ushr 48).toByte(), (seq ushr 40).toByte(), (seq ushr 32).toByte(),
            (seq ushr 24).toByte(), (seq ushr 16).toByte(), (seq ushr 8).toByte(), seq.toByte(),
        ))
        return buf.toByteArray()
    }

    /**
     * Builds a serialized kseal.v1.RequestProof proto signed with [proofKey].
     * Field encoding: (field << 3 | wire_type)
     *   1: string trust_token_id  (wire 2)
     *   2: bytes  request_hash    (wire 2)
     *   3: bytes  nonce           (wire 2)
     *   4: bytes  app_instance_signature (wire 2)
     *   5: int64  monotonic_sequence     (wire 0 = varint)
     */
    private fun buildProof(tokenId: String, requestHash: ByteArray, proofKey: ByteArray): ByteArray {
        val nonce = ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }
        val seq = proofSequence.incrementAndGet()
        val preimage = buildProofPreimage(tokenId, requestHash, nonce, seq)
        val sig = hmacSha256(proofKey, preimage)

        val buf = java.io.ByteArrayOutputStream()
        fun writeTag(field: Int, wireType: Int) { buf.write(byteArrayOf(((field shl 3) or wireType).toByte())) }
        fun writeLd(field: Int, b: ByteArray) {
            writeTag(field, 2)
            var len = b.size
            do { val v = len and 0x7F; len = len ushr 7; buf.write(if (len > 0) v or 0x80 else v) } while (len > 0)
            buf.write(b)
        }
        fun writeVarint(field: Int, v: Long) {
            writeTag(field, 0)
            var rem = v
            do { val b = (rem and 0x7F).toInt(); rem = rem ushr 7; buf.write(if (rem > 0) b or 0x80 else b) } while (rem > 0)
        }
        writeLd(1, tokenId.toByteArray(Charsets.UTF_8))
        writeLd(2, requestHash)
        writeLd(3, nonce)
        writeLd(4, sig)
        writeVarint(5, seq)
        return buf.toByteArray()
    }

    /** Stable, non-PII instance id persisted across runs. */
    private fun stableInstanceId(): String {
        val prefs = getSharedPreferences("kseal-quickstart", MODE_PRIVATE)
        return prefs.getString("instance_id", null) ?: UUID.randomUUID().toString().also {
            prefs.edit().putString("instance_id", it).apply()
        }
    }
}
