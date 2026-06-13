package io.kseal.gradle.internal

import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class RegistryClientTest {

    private lateinit var server: HttpServer
    private var lastPath: String? = null
    private var lastAuth: String? = null
    private var lastBody: String? = null
    private var responseStatus = 200
    private var responseBody = """{"build":{"id":"build-123"}}"""

    @BeforeEach
    fun start() {
        server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/") { exchange ->
            lastPath = exchange.requestURI.path
            lastAuth = exchange.requestHeaders.getFirst("Authorization")
            lastBody = exchange.requestBody.readBytes().toString(Charsets.UTF_8)
            val bytes = responseBody.toByteArray()
            exchange.sendResponseHeaders(responseStatus, bytes.size.toLong())
            exchange.responseBody.use { it.write(bytes) }
        }
        server.start()
    }

    @AfterEach
    fun stop() = server.stop(0)

    private fun baseUrl() = "http://127.0.0.1:${server.address.port}"

    private fun input() = RegistryClient.CreateBuildInput(
        tenantId = "tenant-1",
        appId = "app-1",
        buildHash = "abc123",
        versionName = "1.0.0",
        versionCode = 7,
        protectionProfileId = "profile-1",
        manifestJson = """{"schema":"kseal.build-proof/v1"}""",
    )

    @Test
    fun `posts to the connect procedure with bearer auth and correct payload`() {
        val client = RegistryClient(baseUrl(), apiKey = "ksk_id_secret")
        val result = client.createBuild(input())

        assertEquals("build-123", result.buildId)
        assertEquals("/kseal.v1.RegistryService/CreateBuild", lastPath)
        assertEquals("Bearer ksk_id_secret", lastAuth)

        @Suppress("UNCHECKED_CAST")
        val body = Json.parse(lastBody!!) as Map<String, Any?>
        assertEquals("tenant-1", body["tenant_id"])
        assertEquals("app-1", body["app_id"])
        assertEquals("abc123", body["build_hash"])
        // int64 is encoded as a JSON string per the protobuf-JSON mapping.
        assertEquals("7", body["version_code"])
        assertTrue((body["manifest"] as String).contains("kseal.build-proof/v1"))
    }

    @Test
    fun `non-2xx responses raise RegistryException`() {
        responseStatus = 401
        responseBody = """{"code":"unauthenticated","message":"bad key"}"""
        val client = RegistryClient(baseUrl(), apiKey = "bad")
        val ex = assertThrows(RegistryException::class.java) { client.createBuild(input()) }
        assertTrue(ex.message?.contains("401") == true)
        assertTrue(ex.message?.contains("unauthenticated") == true)
    }
}
