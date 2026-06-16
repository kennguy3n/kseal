package io.kseal.gradle

import javax.inject.Inject
import org.gradle.api.Action
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.model.ObjectFactory
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property

/**
 * Public DSL for the kseal Android hardening plugin.
 *
 * ```
 * ksealHarden {
 *     injectSdk.set(true)
 *     sdkVersion.set("0.1.0")
 *     keepStringKeys.add("app_name")            // never obfuscate these resource keys
 *     registry {
 *         endpoint.set("https://control.kseal.io")
 *         tenantId.set("...")
 *         appId.set("...")
 *         offline.set(false)                    // offline => write manifest, skip network
 *     }
 *     polymorphism { randomize.set(false) }      // deterministic per build content (default)
 * }
 * ```
 *
 * When applied alongside `com.android.application`, the app's package id, version
 * and post-R8 artifacts (classes, resources, `mapping.txt`, keep rules) are wired
 * automatically. The manual input properties below let the same tasks run in
 * non-AGP contexts (e.g. fixtures / specialised pipelines).
 */
abstract class KsealHardenExtension @Inject constructor(objects: ObjectFactory) {

    /** Master switch; when false the plugin registers no work. */
    abstract val enabled: Property<Boolean>

    // ---- SDK injection ----
    abstract val injectSdk: Property<Boolean>
    abstract val sdkGroup: Property<String>
    abstract val sdkName: Property<String>
    abstract val sdkVersion: Property<String>

    // ---- App identity (auto-filled from AGP; override for manual mode) ----
    abstract val packageId: Property<String>
    abstract val versionName: Property<String>
    abstract val versionCode: Property<Long>

    // ---- Keep rules ----
    /** ProGuard/R8 keep-rule files whose `-keep*` directives are honoured. */
    abstract val keepRuleFiles: ConfigurableFileCollection
    /** Extra string-resource keys (glob-capable) that must never be obfuscated. */
    abstract val keepStringKeys: ListProperty<String>

    // ---- Manual input wiring (optional when AGP provides these) ----
    abstract val mappingFile: RegularFileProperty
    abstract val resourcesDir: DirectoryProperty
    abstract val classesDirs: ConfigurableFileCollection

    /**
     * Roots containing the app's native libraries (`<abi>/lib*.so`), e.g. the
     * merged `jniLibs` output. Each `.so` is verified for CFI/MTE/BTI/PAC
     * hardening and recorded in the build proof. Left to the DSL (like
     * [classesDirs]/[resourcesDir]) so the plugin never guesses AGP's
     * version-specific intermediate layout.
     */
    abstract val nativeLibsDirs: ConfigurableFileCollection

    val polymorphism: PolymorphismOptions = objects.newInstance(PolymorphismOptions::class.java)
    val obfuscation: ObfuscationOptions = objects.newInstance(ObfuscationOptions::class.java)
    val registry: RegistryOptions = objects.newInstance(RegistryOptions::class.java)
    val masvsReport: MasvsReportOptions = objects.newInstance(MasvsReportOptions::class.java)

    fun polymorphism(action: Action<PolymorphismOptions>) = action.execute(polymorphism)
    fun obfuscation(action: Action<ObfuscationOptions>) = action.execute(obfuscation)
    fun registry(action: Action<RegistryOptions>) = action.execute(registry)
    fun masvsReport(action: Action<MasvsReportOptions>) = action.execute(masvsReport)
}

/**
 * Bytecode control-flow obfuscation controls (string-constant encryption,
 * opaque predicates, and — at `high` — dispatcher-based control-flow flattening
 * plus light mixed-boolean-arithmetic). **Off by default** and fully fail-safe:
 * when [enabled] is false the classes pass through unchanged. Every pass is name-
 * and mapping-preserving, so R8's `mapping.txt` keeps resolving for crash
 * symbolication. kseal deliberately stops short of VM/dispatcher virtualization
 * (see `docs/build-hardening-android.md`).
 */
abstract class ObfuscationOptions {
    /** Master switch for the bytecode obfuscation pass. Default false. */
    abstract val enabled: Property<Boolean>

    /**
     * Strength: `low` (string encryption only — the safe default), `medium`
     * (adds opaque predicates to a subset of methods) or `high` (opaque
     * predicates on every eligible method, plus control-flow flattening and
     * mixed-boolean-arithmetic on methods that can be flattened safely).
     * Case-insensitive.
     */
    abstract val strength: Property<String>

    /** Exact string literals that must never be encrypted (e.g. reflection keys). */
    abstract val keepStrings: ListProperty<String>
}

/** Per-build polymorphism seed controls. */
abstract class PolymorphismOptions {
    /**
     * A pinned 64-hex-char (32-byte) seed for fully reproducible builds/tests.
     * Leave unset for derived/random seeds.
     */
    abstract val explicitSeedHex: Property<String>

    /**
     * When true a fresh random seed is generated every build (maximum
     * polymorphism, but the seed/manifest are not reproducible and the seed task
     * is never `UP-TO-DATE`). Default false: derive deterministically from inputs.
     */
    abstract val randomize: Property<Boolean>

    /**
     * Name of the Gradle property / env var holding a per-tenant master key (hex)
     * mixed into seed derivation so the seed is unpredictable to an attacker while
     * staying deterministic for identical inputs. Never stored in the manifest.
     */
    abstract val masterKeyProperty: Property<String>
    abstract val masterKeyEnv: Property<String>
}

/** Build-proof registration controls (`RegistryService.CreateBuild`). */
abstract class RegistryOptions {
    abstract val endpoint: Property<String>
    abstract val tenantId: Property<String>
    abstract val appId: Property<String>
    abstract val protectionProfileId: Property<String>

    /** When true (or when no endpoint is set), the manifest is written but not uploaded. */
    abstract val offline: Property<Boolean>

    /** Names of the Gradle property / env var holding the control-plane API key. */
    abstract val apiKeyProperty: Property<String>
    abstract val apiKeyEnv: Property<String>
}

/**
 * Optional MASVS evidence-report generation, run after the build proof is
 * written. Disabled unless [enabled] is set and [executable] points at a built
 * `masvs-report` binary, so projects opt in explicitly.
 */
abstract class MasvsReportOptions {
    /** Master switch for the report task. Default false. */
    abstract val enabled: Property<Boolean>

    /** Path to the built `masvs-report` executable. */
    abstract val executable: Property<String>

    /** MASVS control catalog markdown (defaults to the repo's `docs/masvs-mapping.md`). */
    abstract val catalogFile: RegularFileProperty
}
