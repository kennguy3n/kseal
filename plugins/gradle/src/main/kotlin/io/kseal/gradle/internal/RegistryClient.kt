package io.kseal.gradle.internal

import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/**
 * Minimal client for `RegistryService.CreateBuild`, consumed over HTTPS using the
 * Connect unary JSON protocol (a plain `POST <base>/kseal.v1.RegistryService/CreateBuild`
 * with an `application/json` body). The plugin only ever *consumes* this existing
 * API; it never modifies the service.
 *
 * The API key is supplied by the caller (Gradle property / env var) and sent as a
 * Bearer token; it is never logged. `version_code` and `created_at` are int64
 * fields and are encoded/decoded as JSON strings per the protobuf-JSON mapping
 * that connect-go uses.
 */
internal class RegistryClient(
    private val baseUrl: String,
    private val apiKey: String,
    private val httpClient: HttpClient = defaultClient(),
    private val requestTimeout: Duration = Duration.ofSeconds(30),
) {
    data class CreateBuildInput(
        val tenantId: String,
        val appId: String,
        val buildHash: String,
        val versionName: String,
        val versionCode: Long,
        val protectionProfileId: String,
        val manifestJson: String,
    )

    data class CreateBuildResult(
        val buildId: String,
        val httpStatus: Int,
        val rawResponse: String,
    )

    val procedureUrl: String
        get() = baseUrl.trimEnd('/') + PROCEDURE

    fun createBuild(input: CreateBuildInput): CreateBuildResult {
        val body = Json.write(
            linkedMapOf<String, Any?>(
                "tenant_id" to input.tenantId,
                "app_id" to input.appId,
                "build_hash" to input.buildHash,
                "version_name" to input.versionName,
                // int64 -> JSON string (protobuf JSON mapping).
                "version_code" to input.versionCode.toString(),
                "protection_profile_id" to input.protectionProfileId,
                "manifest" to input.manifestJson,
            ),
            indent = false,
        )

        val request = HttpRequest.newBuilder()
            .uri(URI.create(procedureUrl))
            .timeout(requestTimeout)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("Authorization", "Bearer $apiKey")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build()

        val response = httpClient.send(request, HttpResponse.BodyHandlers.ofString())
        val status = response.statusCode()
        val text = response.body() ?: ""
        if (status !in 200..299) {
            throw RegistryException("CreateBuild failed: HTTP $status ${connectError(text)}")
        }
        val buildId = extractBuildId(text)
        return CreateBuildResult(buildId = buildId, httpStatus = status, rawResponse = text)
    }

    private fun extractBuildId(responseBody: String): String {
        val root = Json.parse(responseBody) as? Map<*, *>
            ?: throw RegistryException("CreateBuild returned a non-object response")
        val build = root["build"] as? Map<*, *>
            ?: throw RegistryException("CreateBuild response missing 'build'")
        return (build["id"] as? String).orEmpty()
    }

    private fun connectError(body: String): String {
        val root = Json.parse(body) as? Map<*, *> ?: return body.take(256)
        val message = root["message"] as? String
        val code = root["code"] as? String
        return listOfNotNull(code?.let { "code=$it" }, message?.let { "message=$it" })
            .joinToString(" ")
            .ifBlank { body.take(256) }
    }

    companion object {
        const val PROCEDURE = "/kseal.v1.RegistryService/CreateBuild"

        private fun defaultClient(): HttpClient =
            HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build()
    }
}

internal class RegistryException(message: String) : RuntimeException(message)
