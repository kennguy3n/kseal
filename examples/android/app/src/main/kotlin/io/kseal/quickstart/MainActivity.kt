package io.kseal.quickstart

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import io.kseal.quickstart.databinding.ActivityMainBinding
import io.kseal.sdk.KsealOptions
import io.kseal.sdk.KsealSDK
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.Executors

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

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        binding.runButton.setOnClickListener { binding.runButton.isEnabled = false; runFlow() }
    }

    private fun log(line: String) = runOnUiThread {
        binding.output.append(line + "\n")
    }

    private fun runFlow() = io.execute() {
        try {
            // 1. Initialize the SDK (no network at launch).
            val sdk = KsealSDK.initialize(
                context = applicationContext,
                tenantId = BuildConfig.KSEAL_TENANT,
                appId = BuildConfig.KSEAL_APP,
                apiKey = BuildConfig.KSEAL_API_KEY,
                options = KsealOptions(buildHash = "sha256:dev-build"),
            )

            // 2. Evaluate local integrity (offline, cheap).
            val risk = sdk.evaluateRisk()
            log("[risk] trustLevel=${risk.trustLevel} score=${risk.score} clean=${risk.isClean} signals=${risk.signals.size}")

            // 3. Trust session over HTTP (host-owned transport).
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
            )

            if (!session.accepted) {
                log("[trust] rejected: ${session.rejectionReason}")
                log("        expected with the dev attestation provider; set -PksealGcpProject=<n> for real Play Integrity.")
                return@execute
            }
            log("[trust] accepted token=${session.tokenId.take(8)}…")

            // 4. Bind a protected request to the trust token.
            sdk.setTrustToken(session.tokenId)
            val requestHash = sha256("POST /v1/orders")
            val proof = sdk.getRequestProof(requestHash)
            val decision = client.validateRequestProof(proof.proofBytes)
            log("[proof] decision=${decision.decision} reason=${decision.reason}")
        } catch (t: Throwable) {
            log("[error] ${t.message}")
        } finally {
            runOnUiThread { binding.runButton.isEnabled = true }
        }
    }

    private fun sha256(s: String): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(s.toByteArray(Charsets.UTF_8))

    /** Stable, non-PII instance id persisted across runs. */
    private fun stableInstanceId(): String {
        val prefs = getSharedPreferences("kseal-quickstart", MODE_PRIVATE)
        return prefs.getString("instance_id", null) ?: UUID.randomUUID().toString().also {
            prefs.edit().putString("instance_id", it).apply()
        }
    }
}
