package io.kseal.quickstart

import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import com.google.android.play.core.integrity.IntegrityTokenResponse
import android.content.Context
import android.util.Base64
import com.google.android.gms.tasks.Tasks

/**
 * Produces the EXTERNAL platform attestation token submitted to VerifyAttestation.
 * This is the one third-party dependency in the flow; everything else is real
 * kseal code. Implementations return the token bytes bound to [nonce].
 */
interface AttestationTokenProvider {
    fun attestationToken(nonce: ByteArray): ByteArray
}

/**
 * Real default: Google Play Integrity. Requires a Play-distributed (or
 * internal-test) build and the app's Google Cloud project number. The verdict
 * JWS is what the server's PlayIntegrityVerifier validates against Google's JWKS.
 */
class PlayIntegrityTokenProvider(
    context: Context,
    private val cloudProjectNumber: Long,
) : AttestationTokenProvider {
    private val manager = IntegrityManagerFactory.create(context.applicationContext)

    override fun attestationToken(nonce: ByteArray): ByteArray {
        // Play Integrity expects a URL-safe, unpadded nonce string.
        val nonceString = Base64.encodeToString(nonce, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
        val request = IntegrityTokenRequest.builder()
            .setNonce(nonceString)
            .setCloudProjectNumber(cloudProjectNumber)
            .build()
        val response: IntegrityTokenResponse = Tasks.await(manager.requestIntegrityToken(request))
        return response.token().toByteArray(Charsets.UTF_8)
    }
}

/**
 * Local-dev fake used when no Google Cloud project number is configured. It
 * cannot mint a Google-signed verdict, so a stock server will (correctly)
 * reject the attestation — fail-closed. Use it to exercise the GetNonce /
 * request-proof plumbing offline; for a fully runnable mocked chain see the
 * backend-quickstart, which swaps the server's JWKS source per the documented
 * test path.
 */
class DevAttestationTokenProvider : AttestationTokenProvider {
    override fun attestationToken(nonce: ByteArray): ByteArray =
        ("dev-attestation:" + Base64.encodeToString(nonce, Base64.NO_WRAP)).toByteArray(Charsets.UTF_8)
}
