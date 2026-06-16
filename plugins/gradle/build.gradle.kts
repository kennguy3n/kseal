import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.gradle.api.tasks.testing.logging.TestLogEvent

plugins {
    `kotlin-dsl`
    `java-gradle-plugin`
    `maven-publish`
}

group = "io.kseal"
version = libs.versions.ksealSdk.get()

dependencies {
    // R8/JVM class transforms (debug-metadata stripping) use ASM. Real dependency,
    // resolved from mavenCentral; bundled into the plugin runtime classpath.
    implementation(libs.asm)
    implementation(libs.asm.commons)
    // Tree + dataflow-analysis APIs back the HIGH-tier control-flow-flattening
    // and MBA passes (basic-block reconstruction + frame/stack reasoning).
    implementation(libs.asm.tree)
    implementation(libs.asm.analysis)

    // AGP variant API is compile-only: the plugin soft-wires into the Android
    // build only when `com.android.application` is applied (see AgpIntegration),
    // so the AGP classes are never loaded for non-Android consumers.
    compileOnly(libs.agp.api)

    testImplementation(libs.junit.jupiter)
    testImplementation(gradleTestKit())
    testRuntimeOnly(libs.junit.platform.launcher)
}

gradlePlugin {
    plugins {
        create("ksealAndroidHarden") {
            id = "io.kseal.android.harden"
            implementationClass = "io.kseal.gradle.KsealAndroidHardenPlugin"
            displayName = "kseal Android build-time hardening"
            description = "R8-aware Android build hardening: per-build polymorphism, " +
                "string/resource obfuscation, debug-metadata stripping, build-proof " +
                "manifest emission, and registration via RegistryService.CreateBuild."
        }
    }
}

// Functional (TestKit) tests live in their own source set so they can be run and
// cached independently of the fast unit tests.
val functionalTest: SourceSet by sourceSets.creating

configurations[functionalTest.implementationConfigurationName]
    .extendsFrom(configurations.testImplementation.get())
configurations[functionalTest.runtimeOnlyConfigurationName]
    .extendsFrom(configurations.testRuntimeOnly.get())

val functionalTestTask = tasks.register<Test>("functionalTest") {
    group = "verification"
    description = "Runs the Gradle TestKit functional tests against the fixture app."
    testClassesDirs = functionalTest.output.classesDirs
    classpath = functionalTest.runtimeClasspath
    useJUnitPlatform()
    // Functional tests launch real Gradle builds; keep them off the build cache
    // because their inputs include the plugin-under-test classpath.
    outputs.upToDateWhen { false }
    shouldRunAfter(tasks.named("test"))
}

// Expose the plugin-under-test metadata to the functional source set.
gradlePlugin.testSourceSets(functionalTest)

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
    testLogging {
        events(TestLogEvent.PASSED, TestLogEvent.SKIPPED, TestLogEvent.FAILED)
        exceptionFormat = TestExceptionFormat.FULL
        showStandardStreams = true
    }
}

tasks.named("check") {
    dependsOn(functionalTestTask)
}

kotlin {
    jvmToolchain(17)
}
