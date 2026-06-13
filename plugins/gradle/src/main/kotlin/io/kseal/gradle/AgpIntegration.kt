package io.kseal.gradle

import com.android.build.api.artifact.SingleArtifact
import com.android.build.api.variant.ApplicationAndroidComponentsExtension
import org.gradle.api.Project

/**
 * Soft integration with the Android Gradle Plugin.
 *
 * Instantiated only from within `pluginManager.withPlugin("com.android.application")`,
 * so the AGP types referenced here are never loaded for non-Android consumers.
 * It fills in defaults from the (release) variant — application id, version, the
 * R8 obfuscation mapping file — and injects the kseal Android SDK dependency.
 *
 * All wiring uses Gradle *conventions*, so anything the user sets explicitly in
 * the `ksealHarden { … }` DSL takes precedence. Classes and resource directories
 * are left to the DSL (pointed at the desired variant artifacts) so the plugin
 * never guesses at version-specific intermediate layouts.
 */
internal class AgpIntegration(
    private val project: Project,
    private val ext: KsealHardenExtension,
    private val tasks: KsealAndroidHardenPlugin.KsealTasks,
) {
    fun wire() {
        injectSdkDependency()

        val androidComponents = project.extensions.findByType(ApplicationAndroidComponentsExtension::class.java)
            ?: return

        androidComponents.onVariants(androidComponents.selector().withBuildType("release")) { variant ->
            ext.packageId.convention(variant.applicationId)

            val mainOutput = variant.outputs.firstOrNull()
            if (mainOutput != null) {
                ext.versionName.convention(mainOutput.versionName.orElse("0.0.0"))
                ext.versionCode.convention(mainOutput.versionCode.map { it.toLong() }.orElse(0L))
            }

            // R8 mapping (only produced when minification is enabled). Optional input.
            ext.mappingFile.convention(variant.artifacts.get(SingleArtifact.OBFUSCATION_MAPPING_FILE))

            project.logger.info("kseal: wired into Android variant '${variant.name}'")
        }
    }

    private fun injectSdkDependency() {
        if (!ext.injectSdk.getOrElse(true)) return
        val group = ext.sdkGroup.getOrElse("io.kseal")
        val name = ext.sdkName.getOrElse("kseal-android")
        val version = ext.sdkVersion.getOrElse(KsealAndroidHardenPlugin.PLUGIN_VERSION)
        project.dependencies.add("implementation", "$group:$name:$version")
        project.logger.info("kseal: injected SDK dependency $group:$name:$version")
    }
}
