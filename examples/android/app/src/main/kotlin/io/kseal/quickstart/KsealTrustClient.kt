package io.kseal.quickstart

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.Base64

/** Minted trust session returned by VerifyAttestation. */
data class TrustSession(val accepted: Boolean, val tokenId: String, val rejectionReason: String)

/** Server decision after validating a request proof. */
data class ProofDecision(val decision: String, val reason: String)

/**
 * Drives the host-owned TrustService trust flow over Connect's HTTP/JSON (and,
 * for the proof, HTTP/proto) surface. The Android SDK deliberately ships no
 * network client — the host owns transport, pinning, and retries — so this is
 * the documented integration the SDK README points to.
 */
class KsealTrustClient(
    private val baseUrl: String,
    private val tenantId: String,
    private val appId: String,
    private val apiKey: String,
    private val http: OkHttpClient = OkHttpClient(),
) {
    private val json = "application/json".toMediaType()
    private val proto = "application/proto".toMediaType()

    /** GetNonce → single-use challenge bytes. */
    fun getNonce(): ByteArray {
        val body = JSONObject()
            .put("tenant_id", tenantId)
            .put("app_id", appId)
            .put("platform", "PLATFORM_ANDROID")
            .toString()
        val resp = post("TrustService/GetNonce", body.toByteArray(), json, auth = false)
        val nonce = JSONObject(String(resp, Charsets.UTF_8)).getString("nonce")
        return Base64.getDecoder().decode(nonce)
    }

    /** VerifyAttestation → minted trust session. */
    fun verifyAttestation(
        nonce: ByteArray,
        buildHash: String,
        instanceId: String,
        attestationToken: ByteArray,
    ): TrustSession {
        val body = JSONObject()
            .put("tenant_id", tenantId)
            .put("app_id", appId)
            .put("platform", "PLATFORM_ANDROID")
            .put("nonce", b64(nonce))
            .put("build_hash", buildHash)
            .put("instance_id", instanceId)
            .put("platform_attestation_token", b64(attestationToken))
            .toString()
        val resp = post("TrustService/VerifyAttestation", body.toByteArray(), json, auth = false)
        // Connect serializes proto messages as JSON with camelCase field names
        // (protojson default), so read trustToken/tokenId/rejectionReason — not
        // the snake_case proto names.
        val obj = JSONObject(String(resp, Charsets.UTF_8))
        val token = obj.optJSONObject("trustToken")?.optString("tokenId").orEmpty()
        return TrustSession(
            accepted = obj.optBoolean("accepted", false),
            tokenId = token,
            rejectionReason = obj.optString("rejectionReason"),
        )
    }

    /**
     * ValidateRequestProof. [proofBytes] is the serialized kseal.v1.RequestProof
     * produced by the SDK, posted as binary proto so the host never has to
     * re-encode the signed structure. The response is a binary RequestProofResult.
     */
    fun validateRequestProof(proofBytes: ByteArray): ProofDecision {
        val resp = post("TrustService/ValidateRequestProof", proofBytes, proto, auth = false)
        return parseDecision(resp)
    }

    private fun post(method: String, body: ByteArray, mediaType: okhttp3.MediaType, auth: Boolean): ByteArray {
        val builder = Request.Builder()
            .url("$baseUrl/kseal.v1.$method")
            .post(body.toRequestBody(mediaType))
        if (auth && apiKey.isNotEmpty()) builder.header("Authorization", "Bearer $apiKey")
        http.newCall(builder.build()).execute().use { response ->
            val bytes = response.body?.bytes() ?: ByteArray(0)
            if (!response.isSuccessful) {
                throw RuntimeException("$method failed (${response.code}): ${String(bytes, Charsets.UTF_8)}")
            }
            return bytes
        }
    }

    private fun b64(b: ByteArray): String = Base64.getEncoder().encodeToString(b)

    /**
     * Reads the `decision` (field 1, enum varint) and `reason` (field 2, string)
     * from a binary RequestProofResult — a few bytes, so a tiny field reader
     * avoids pulling generated protobuf classes into the sample.
     */
    private fun parseDecision(bytes: ByteArray): ProofDecision {
        var i = 0
        var decision = 0
        var reason = ""
        while (i < bytes.size) {
            val tag = bytes[i].toInt() and 0xff; i++
            val field = tag ushr 3
            when (tag and 0x7) {
                0 -> { // varint
                    var shift = 0; var v = 0L
                    while (i < bytes.size) {
                        val b = bytes[i].toInt() and 0xff; i++
                        v = v or ((b.toLong() and 0x7f) shl shift)
                        if (b and 0x80 == 0) break
                        shift += 7
                    }
                    if (field == 1) decision = v.toInt()
                }
                2 -> { // length-delimited
                    var shift = 0; var len = 0
                    while (i < bytes.size) {
                        val b = bytes[i].toInt() and 0xff; i++
                        len = len or ((b and 0x7f) shl shift)
                        if (b and 0x80 == 0) break
                        shift += 7
                    }
                    val s = String(bytes, i, len, Charsets.UTF_8); i += len
                    if (field == 2) reason = s
                }
                1 -> i += 8 // fixed64 — skip so an added wide field can't stall the scan
                5 -> i += 4 // fixed32 — skip
                else -> break // group/unknown wire type — stop
            }
        }
        val name = when (decision) {
            1 -> "ALLOW"
            2 -> "STEP_UP"
            3 -> "DENY"
            else -> "UNSPECIFIED"
        }
        return ProofDecision(name, reason)
    }
}
