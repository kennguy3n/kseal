package io.kseal.gradle

import io.kseal.gradle.tasks.BuildProofManifestTask
import io.kseal.gradle.tasks.GenerateMasvsReportTask
import io.kseal.gradle.tasks.GeneratePolymorphismSeedTask
import io.kseal.gradle.tasks.HardenNativeLibrariesTask
import io.kseal.gradle.tasks.HardenResourcesTask
import io.kseal.gradle.tasks.RegisterBuildTask
import io.kseal.gradle.tasks.StripDebugMetadataTask
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.provider.Provider
import org.gradle.kotlin.dsl.register

/**
 * kseal Android build-time hardening plugin.
 *
 * Registers the hardening pipeline — seed → (strip debug | harden resources) →
 * build-proof manifest → register — as incremental, cacheable Gradle tasks. When
 * `com.android.application` is also applied the app identity, R8 mapping and SDK
 * injection are wired automatically (see [AgpIntegration]); the same tasks also
 * run in plain projects via the DSL's manual input properties, which is what the
 * functional tests exercise.
 *
 * The plugin never hard-depends on AGP: all Android Gradle Plugin types are
 * touched only inside the `withPlugin("com.android.application")` callback.
 */
class KsealAndroidHardenPlugin : Plugin<Project> {

    override fun apply(project: Project) {
        val ext = project.extensions.create("ksealHarden", KsealHardenExtension::class.java)
        applyConventions(project, ext)

        val tasks = registerTasks(project, ext)

        // Soft-wire into the Android application build when present.
        project.pluginManager.withPlugin("com.android.application") {
            AgpIntegration(project, ext, tasks).wire()
        }
    }

    private fun applyConventions(project: Project, ext: KsealHardenExtension) {
        ext.enabled.convention(true)
        ext.injectSdk.convention(true)
        ext.sdkGroup.convention("io.kseal")
        ext.sdkName.convention("kseal-android")
        ext.sdkVersion.convention(project.providers.provider { PLUGIN_VERSION })
        ext.versionName.convention("0.0.0")
        ext.versionCode.convention(0L)
        ext.packageId.convention("")

        ext.polymorphism.randomize.convention(false)
        ext.polymorphism.masterKeyProperty.convention("kseal.polySeedKey")
        ext.polymorphism.masterKeyEnv.convention("KSEAL_POLY_SEED_KEY")

        ext.registry.offline.convention(false)
        ext.registry.protectionProfileId.convention("")
        ext.registry.apiKeyProperty.convention("kseal.apiKey")
        ext.registry.apiKeyEnv.convention("KSEAL_API_KEY")

        ext.masvsReport.enabled.convention(false)
    }

    private fun registerTasks(project: Project, ext: KsealHardenExtension): KsealTasks {
        val layout = project.layout
        val providers = project.providers
        val ksealOut = layout.buildDirectory.dir("kseal")
        // Capture providers (not the extension) so the onlyIf / upToDateWhen specs
        // remain configuration-cache compatible.
        val enabledProvider = ext.enabled
        val randomizeProvider = ext.polymorphism.randomize

        val seed = project.tasks.register<GeneratePolymorphismSeedTask>("ksealGeneratePolymorphismSeed") {
            group = GROUP
            description = "Generates the per-build polymorphism seed."
            onlyIf { enabledProvider.getOrElse(true) }
            hardeningInputs.from(ext.classesDirs, ext.keepRuleFiles)
            // Optional single-file/dir inputs: contribute nothing when unset rather
            // than failing dependency resolution.
            hardeningInputs.from(ext.resourcesDir.map { listOf(it) }.orElse(emptyList()))
            hardeningInputs.from(ext.mappingFile.map { listOf(it) }.orElse(emptyList()))
            explicitSeedHex.set(ext.polymorphism.explicitSeedHex)
            randomize.set(ext.polymorphism.randomize)
            projectSalt.set(providers.provider { "${project.group}:${project.name}" })
            masterKeyHex.set(secret(project, ext.polymorphism.masterKeyProperty, ext.polymorphism.masterKeyEnv))
            seedFile.set(ksealOut.map { it.file("seed/seed.hex") })
            seedDigestFile.set(ksealOut.map { it.file("seed/seed-digest.txt") })
            seedMetaFile.set(ksealOut.map { it.file("seed/seed-meta.json") })
            // A random seed must regenerate every build; a derived seed is UP-TO-DATE
            // when inputs are unchanged.
            outputs.upToDateWhen { !randomizeProvider.getOrElse(false) }
        }

        val resources = project.tasks.register<HardenResourcesTask>("ksealHardenResources") {
            group = GROUP
            description = "R8-aware string/resource obfuscation."
            onlyIf { enabledProvider.getOrElse(true) }
            resourcesDir.set(ext.resourcesDir)
            mappingFile.set(ext.mappingFile)
            keepRuleFiles.from(ext.keepRuleFiles)
            keepStringKeys.set(ext.keepStringKeys)
            seedFile.set(seed.flatMap { it.seedFile })
            hardenedResourcesDir.set(ksealOut.map { it.dir("hardened/res") })
            sealedStringsFile.set(ksealOut.map { it.file("hardened/assets/kseal/strings.sealed") })
            mappingOutFile.set(ksealOut.map { it.file("hardened/mapping.txt") })
            reportFile.set(ksealOut.map { it.file("reports/resources.json") })
        }

        val classes = project.tasks.register<StripDebugMetadataTask>("ksealStripDebugMetadata") {
            group = GROUP
            description = "Strips debug metadata from compiled classes."
            onlyIf { enabledProvider.getOrElse(true) }
            classes.from(ext.classesDirs)
            strippedClassesDir.set(ksealOut.map { it.dir("hardened/classes") })
            reportFile.set(ksealOut.map { it.file("reports/classes.json") })
        }

        val native = project.tasks.register<HardenNativeLibrariesTask>("ksealHardenNativeLibraries") {
            group = GROUP
            description = "Verifies CFI/MTE/BTI/PAC hardening of native libraries and records it in the build proof."
            onlyIf { enabledProvider.getOrElse(true) }
            nativeLibDirs.from(ext.nativeLibsDirs)
            hardenedNativeDir.set(ksealOut.map { it.dir("hardened/native") })
            reportFile.set(ksealOut.map { it.file("reports/native.json") })
        }

        val manifest = project.tasks.register<BuildProofManifestTask>("ksealBuildProofManifest") {
            group = GROUP
            description = "Emits the build-proof manifest and computes the build hash."
            onlyIf { enabledProvider.getOrElse(true) }
            platform.set("android")
            packageId.set(ext.packageId)
            versionName.set(ext.versionName)
            versionCode.set(ext.versionCode)
            sdkName.set(ext.sdkName)
            sdkVersion.set(ext.sdkVersion)
            pluginVersion.set(PLUGIN_VERSION)
            gradleVersion.set(project.gradle.gradleVersion)
            javaVersion.set(System.getProperty("java.version"))
            r8MappingPresent.set(ext.mappingFile.map { it.asFile.isFile }.orElse(false))
            seedDigestFile.set(seed.flatMap { it.seedDigestFile })
            seedMetaFile.set(seed.flatMap { it.seedMetaFile })
            transformReports.from(
                classes.flatMap { it.reportFile },
                resources.flatMap { it.reportFile },
                native.flatMap { it.reportFile },
            )
            strippedClassesDir.set(classes.flatMap { it.strippedClassesDir })
            hardenedResourcesDir.set(resources.flatMap { it.hardenedResourcesDir })
            hardenedNativeDir.set(native.flatMap { it.hardenedNativeDir })
            sealedStringsFile.set(resources.flatMap { it.sealedStringsFile })
            mappingOutFile.set(resources.flatMap { it.mappingOutFile })
            manifestFile.set(ksealOut.map { it.file("build-proof/manifest.json") })
            buildHashFile.set(ksealOut.map { it.file("build-proof/build-hash.txt") })
        }

        val register = project.tasks.register<RegisterBuildTask>("ksealRegisterBuild") {
            group = GROUP
            description = "Registers the build proof via RegistryService.CreateBuild (or stages it offline)."
            onlyIf { enabledProvider.getOrElse(true) }
            manifestFile.set(manifest.flatMap { it.manifestFile })
            endpoint.set(ext.registry.endpoint)
            tenantId.set(ext.registry.tenantId)
            appId.set(ext.registry.appId)
            protectionProfileId.set(ext.registry.protectionProfileId)
            offline.set(ext.registry.offline)
            apiKey.set(secret(project, ext.registry.apiKeyProperty, ext.registry.apiKeyEnv))
            receiptFile.set(ksealOut.map { it.file("build-proof/registration-receipt.json") })
            uploadableManifestFile.set(ksealOut.map { it.file("build-proof/uploadable-manifest.json") })
        }

        val masvsEnabled = ext.masvsReport.enabled
        val masvsExecutable = ext.masvsReport.executable
        val masvsReport = project.tasks.register<GenerateMasvsReportTask>("ksealMasvsReport") {
            group = GROUP
            description = "Generates the MASVS evidence report from the build proof (optional; requires masvsReport.executable)."
            onlyIf { enabledProvider.getOrElse(true) && masvsEnabled.getOrElse(false) && masvsExecutable.isPresent }
            executable.set(masvsExecutable)
            manifestFile.set(manifest.flatMap { it.manifestFile })
            catalogFile.set(ext.masvsReport.catalogFile)
            extraArgs.set(emptyList())
            reportMarkdownFile.set(ksealOut.map { it.file("reports/masvs-evidence.md") })
            reportJsonFile.set(ksealOut.map { it.file("reports/masvs-evidence.json") })
        }

        val harden = project.tasks.register("ksealHarden") {
            group = GROUP
            description = "Runs the full kseal hardening pipeline and registers the build proof."
            onlyIf { enabledProvider.getOrElse(true) }
            dependsOn(register)
            // The report is produced when opted in; its onlyIf no-ops otherwise.
            dependsOn(masvsReport)
        }

        return KsealTasks(seed, resources, classes, native, manifest, register, harden)
    }

    /** Resolves a secret from a Gradle property (by name) or, failing that, an env var. */
    private fun secret(
        project: Project,
        propertyName: Provider<String>,
        envName: Provider<String>,
    ): Provider<String> {
        val fromProperty = propertyName.flatMap { project.providers.gradleProperty(it) }
        val fromEnv = envName.flatMap { project.providers.environmentVariable(it) }
        return fromProperty.orElse(fromEnv)
    }

    internal class KsealTasks(
        val seed: org.gradle.api.tasks.TaskProvider<GeneratePolymorphismSeedTask>,
        val resources: org.gradle.api.tasks.TaskProvider<HardenResourcesTask>,
        val classes: org.gradle.api.tasks.TaskProvider<StripDebugMetadataTask>,
        val native: org.gradle.api.tasks.TaskProvider<HardenNativeLibrariesTask>,
        val manifest: org.gradle.api.tasks.TaskProvider<BuildProofManifestTask>,
        val register: org.gradle.api.tasks.TaskProvider<RegisterBuildTask>,
        val harden: org.gradle.api.tasks.TaskProvider<org.gradle.api.Task>,
    )

    companion object {
        const val GROUP = "kseal"
        const val PLUGIN_VERSION = "0.1.0"
    }
}
