package io.kseal.gradle

import com.sun.net.httpserver.HttpServer
import java.io.File
import java.net.InetSocketAddress
import org.gradle.testkit.runner.GradleRunner
import org.gradle.testkit.runner.TaskOutcome
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir

class RegistrationFunctionalTest {

    @TempDir
    lateinit var projectDir: File

    private lateinit var server: HttpServer
    @Volatile private var path: String? = null
    @Volatile private var auth: String? = null
    @Volatile private var body: String? = null

    @BeforeEach
    fun start() {
        server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/") { exchange ->
            path = exchange.requestURI.path
            auth = exchange.requestHeaders.getFirst("Authorization")
            body = exchange.requestBody.readBytes().toString(Charsets.UTF_8)
            val bytes = """{"build":{"id":"build-functional-1"}}""".toByteArray()
            exchange.sendResponseHeaders(200, bytes.size.toLong())
            exchange.responseBody.use { it.write(bytes) }
        }
        server.start()
    }

    @AfterEach
    fun stop() = server.stop(0)

    @Test
    fun `online registration posts manifest to CreateBuild with auth header`() {
        val endpoint = "http://127.0.0.1:${server.address.port}"
        File(projectDir, "settings.gradle.kts").writeText("""rootProject.name = "fixture"""")
        File(projectDir, "build.gradle.kts").writeText(
            """
            plugins { id("io.kseal.android.harden") }
            ksealHarden {
                injectSdk.set(false)
                packageId.set("com.example.fixture")
                versionName.set("2.0.0")
                versionCode.set(200L)
                resourcesDir.set(layout.projectDirectory.dir("res"))
                keepStringKeys.add("app_name")
                polymorphism { explicitSeedHex.set("${"bb".repeat(32)}") }
                registry {
                    endpoint.set("$endpoint")
                    tenantId.set("tenant-xyz")
                    appId.set("app-xyz")
                    protectionProfileId.set("profile-1")
                    offline.set(false)
                }
            }
            """.trimIndent(),
        )
        File(projectDir, "res/values").mkdirs()
        File(projectDir, "res/values/strings.xml").writeText(
            """
            <?xml version="1.0" encoding="utf-8"?>
            <resources><string name="api_secret">hunter2</string></resources>
            """.trimIndent(),
        )

        val result = GradleRunner.create()
            .withProjectDir(projectDir)
            .withPluginClasspath()
            .withArguments("ksealRegisterBuild", "-Pkseal.apiKey=ksk_tenant_secret", "--stacktrace")
            .forwardOutput()
            .build()

        assertEquals(TaskOutcome.SUCCESS, result.task(":ksealRegisterBuild")?.outcome)
        assertEquals("/kseal.v1.RegistryService/CreateBuild", path)
        assertEquals("Bearer ksk_tenant_secret", auth)

        val payload = body!!
        assertTrue(payload.contains("\"tenant_id\":\"tenant-xyz\""))
        assertTrue(payload.contains("\"app_id\":\"app-xyz\""))
        // int64 encoded as a JSON string per protobuf-JSON mapping.
        assertTrue(payload.contains("\"version_code\":\"200\""))
        assertTrue(payload.contains("kseal.build-proof/v1"))

        val receipt = File(projectDir, "build/kseal/build-proof/registration-receipt.json").readText()
        assertTrue(receipt.contains("\"mode\": \"online\""))
        assertTrue(receipt.contains("\"build_id\": \"build-functional-1\""))
    }
}
