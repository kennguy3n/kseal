package io.kseal.gradle.tasks

import io.kseal.gradle.internal.Json
import io.kseal.gradle.internal.RegistryClient
import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction

/**
 * Registers the build proof via `RegistryService.CreateBuild`, or — in offline
 * mode — writes the manifest as an uploadable artifact for later registration.
 *
 * Deliberately **not** `@CacheableTask`: registration is a network side effect and
 * must never be satisfied from a build cache. It is still locally `UP-TO-DATE`
 * when the manifest and outputs are unchanged, so a no-op rebuild does not
 * re-POST. The API key is read from a Gradle property / env var, kept `@Internal`
 * so it never enters an input snapshot, and is never logged.
 */
abstract class RegisterBuildTask : DefaultTask() {

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val manifestFile: RegularFileProperty

    @get:Input
    @get:Optional
    abstract val endpoint: Property<String>

    @get:Input
    @get:Optional
    abstract val tenantId: Property<String>

    @get:Input
    @get:Optional
    abstract val appId: Property<String>

    @get:Input
    @get:Optional
    abstract val protectionProfileId: Property<String>

    @get:Input
    abstract val offline: Property<Boolean>

    /** Control-plane API key (secret) — not a tracked input, never logged. */
    @get:Internal
    abstract val apiKey: Property<String>

    @get:OutputFile
    abstract val receiptFile: RegularFileProperty

    @get:OutputFile
    abstract val uploadableManifestFile: RegularFileProperty

    @TaskAction
    fun register() {
        val manifestText = manifestFile.get().asFile.readText()
        val manifest = Json.parse(manifestText) as? Map<*, *>
            ?: throw GradleException("kseal: manifest is not a JSON object")
        val buildHash = manifest["build_hash"] as? String
            ?: throw GradleException("kseal: manifest missing build_hash")
        val app = manifest["app"] as? Map<*, *> ?: emptyMap<Any, Any>()
        val versionName = (app["version_name"] as? String).orEmpty()
        val versionCode = (app["version_code"] as? Number)?.toLong() ?: 0L

        // Always make the manifest available as an uploadable artifact.
        uploadableManifestFile.get().asFile.writeText(manifestText)

        val ep = endpoint.orNull?.takeIf { it.isNotBlank() }
        if (offline.getOrElse(false) || ep == null) {
            writeReceipt(
                linkedMapOf(
                    "mode" to "offline",
                    "build_hash" to buildHash,
                    "uploadable_manifest" to uploadableManifestFile.get().asFile.absolutePath,
                ),
            )
            logger.lifecycle("kseal: offline mode — manifest staged for later upload (build_hash=${buildHash.take(16)}…)")
            return
        }

        val tenant = tenantId.orNull?.takeIf { it.isNotBlank() }
            ?: throw GradleException("kseal: registry.tenantId is required for online registration")
        val application = appId.orNull?.takeIf { it.isNotBlank() }
            ?: throw GradleException("kseal: registry.appId is required for online registration")
        val key = apiKey.orNull?.takeIf { it.isNotBlank() }
            ?: throw GradleException(
                "kseal: API key not found. Set it via the configured Gradle property or env var, " +
                    "or enable offline mode.",
            )

        val client = RegistryClient(baseUrl = ep, apiKey = key)
        val result = client.createBuild(
            RegistryClient.CreateBuildInput(
                tenantId = tenant,
                appId = application,
                buildHash = buildHash,
                versionName = versionName,
                versionCode = versionCode,
                protectionProfileId = protectionProfileId.orNull.orEmpty(),
                manifestJson = manifestText,
            ),
        )
        writeReceipt(
            linkedMapOf(
                "mode" to "online",
                "endpoint" to client.procedureUrl,
                "build_hash" to buildHash,
                "build_id" to result.buildId,
                "http_status" to result.httpStatus,
            ),
        )
        logger.lifecycle("kseal: registered build ${result.buildId} (build_hash=${buildHash.take(16)}…)")
    }

    private fun writeReceipt(receipt: Map<String, Any?>) {
        receiptFile.get().asFile.writeText(Json.write(receipt))
    }
}
