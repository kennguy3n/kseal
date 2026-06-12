import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.gradle.api.tasks.testing.logging.TestLogEvent

plugins {
    id("com.android.library") version "8.7.3"
    id("org.jetbrains.kotlin.android") version "2.0.21"
}

group = "io.kseal"
version = "0.1.0"

// Repo root, resolved relative to this module (sdk/android).
val repoRoot: File = rootDir.parentFile.parentFile
val rustCoreDir: File = repoRoot.resolve("sdk/rust-core")

android {
    namespace = "io.kseal.sdk"
    compileSdk = 34
    ndkVersion = System.getenv("ANDROID_NDK_VERSION") ?: "26.1.10909125"

    defaultConfig {
        minSdk = 24
        @Suppress("DEPRECATION")
        targetSdk = 34
        consumerProguardFiles("consumer-rules.pro")

        ndk {
            // ABIs we ship the Rust trust core for.
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
        externalNativeBuild {
            cmake {
                arguments += "-DKSEAL_RUST_CORE_DIR=${rustCoreDir.absolutePath}"
            }
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/jni/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    testOptions {
        unitTests {
            isIncludeAndroidResources = true
            isReturnDefaultValues = false
        }
    }

    // The native trust core (.so) is produced by cargo-ndk (see
    // scripts/build-rust-android.sh) into this directory and packaged into the AAR.
    sourceSets["main"].jniLibs.srcDirs("src/main/jniLibs")

    packaging {
        jniLibs {
            // Keep the trust core compact; allow legacy extraction off.
            useLegacyPackaging = false
        }
    }

    lint {
        warningsAsErrors = false
        abortOnError = true
        disable += setOf("GradleDependency", "AndroidGradlePluginVersion", "OldTargetApi")
    }
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation("androidx.annotation:annotation:1.9.1")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.robolectric:robolectric:4.14.1")
    testImplementation("androidx.test:core:1.6.1")
    testImplementation("androidx.test.ext:junit:1.2.1")
}

// ---------------------------------------------------------------------------
// Host-native build of the JNI bridge + Rust trust core for JVM unit tests.
//
// JVM tests cannot load an Android .so, so we compile the *same* JNI bridge
// (src/main/jni/kseal_jni.c) against the host JDK and statically link the Rust
// staticlib (libkseal_ffi.a). The resulting libkseal_jni.so lets the SDK-flow
// integration test exercise the REAL Rust trust core through the REAL JNI
// boundary on the JVM — no device, no faked core.
// ---------------------------------------------------------------------------
val hostJniDir: File = layout.buildDirectory.dir("hostJni").get().asFile

val buildHostJni by tasks.registering(Exec::class) {
    group = "kseal"
    description = "Builds libkseal_jni.so for the test JVM (real Rust core via JNI)."
    workingDir = projectDir
    val script = file("scripts/build-host-jni.sh")
    inputs.file(script)
    inputs.dir(file("src/main/jni"))
    inputs.dir(rustCoreDir.resolve("kseal-ffi/src"))
    inputs.dir(rustCoreDir.resolve("kseal-core/src"))
    outputs.dir(hostJniDir)
    commandLine("bash", script.absolutePath, hostJniDir.absolutePath)
    // Skip gracefully (with a clear message) when the host C toolchain is absent.
    isIgnoreExitValue = false
}

tasks.withType<Test>().configureEach {
    dependsOn(buildHostJni)
    systemProperty("java.library.path", hostJniDir.absolutePath)
    systemProperty("kseal.hostJniDir", hostJniDir.absolutePath)
    testLogging {
        events(TestLogEvent.PASSED, TestLogEvent.SKIPPED, TestLogEvent.FAILED)
        exceptionFormat = TestExceptionFormat.FULL
        showStandardStreams = true
    }
}

// ---------------------------------------------------------------------------
// Android (device) build of the Rust trust core via cargo-ndk.
//
// Produces libkseal_ffi.so per ABI into src/main/jniLibs so CMake/AGP bundle it
// into the AAR. Requires the Android NDK + `cargo-ndk` + rustup Android targets.
// Wired here and runnable via `./gradlew cargoBuildAndroid`; documented in
// scripts/build-rust-android.sh. We never fabricate the artifact.
// ---------------------------------------------------------------------------
@Suppress("unused")
val cargoBuildAndroid by tasks.registering(Exec::class) {
    group = "kseal"
    description = "Cross-compiles the Rust trust core (.so) for Android ABIs via cargo-ndk."
    workingDir = projectDir
    commandLine("bash", file("scripts/build-rust-android.sh").absolutePath)
    isIgnoreExitValue = false
}
// NOTE: not wired into preBuild on purpose — JVM unit tests must not require the
// Android NDK/cargo-ndk toolchain. Run `./gradlew cargoBuildAndroid` (or the
// script directly) before assembling a release AAR so the trust core .so is
// bundled per ABI.
