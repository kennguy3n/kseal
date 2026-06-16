package io.kseal.sdk.probes

import io.kseal.sdk.RiskSignal

/**
 * Detects a malicious or untrusted input method (keyboard) capable of
 * keylogging credentials ([RiskSignal.MALICIOUS_IME]).
 *
 * On Android the *currently selected* IME receives every keystroke the user
 * types — passwords, OTPs, card numbers — so a side-loaded keyboard is a direct
 * credential-exfiltration vector. The check therefore keys off the **active**
 * keyboard (`Settings.Secure.DEFAULT_INPUT_METHOD`): if its package is neither a
 * well-known keyboard nor a platform/OEM system IME namespace, the keyboard is
 * treated as untrusted and [RiskSignal.MALICIOUS_IME] is raised.
 *
 * This is a single, **fusion-weighted** risk signal (not a hard block): the
 * server folds wire bit 19 into its score alongside the other RASP probes, so
 * the detector is deliberately tuned for *precision* — Gboard, SwiftKey, the
 * AOSP keyboard and the common OEM stock keyboards are all allow-listed so the
 * overwhelmingly common legitimate setups never fire.
 *
 * Only the active IME is scored. An enabled-but-not-selected third-party IME
 * cannot capture keystrokes until the user switches to it, so flagging it would
 * dilute this single bit with a lower-confidence condition and add false
 * positives for users who merely have a second keyboard installed; the enabled
 * list is consulted only to disambiguate the active IME when the platform does
 * not expose a default (see [activeImePackage]).
 *
 * Trust is decided from the package name alone — this layer has no signing-info
 * accessor — so a determined attacker could in principle squat a trusted
 * namespace. That is an accepted trade-off for a non-blocking fusion signal:
 * widening trust favours precision (fewer false positives) over catching a
 * spoofed package name, and any cryptographic IME verification would be a
 * separate, contract-level change.
 */
internal class ImeDetector(private val env: DeviceEnvironment) : Probe {

    override val id: String = "ime"

    override fun evaluate(): Set<RiskSignal> {
        val activePackage = activeImePackage() ?: return emptySet()
        return if (isTrustedKeyboard(activePackage)) {
            emptySet()
        } else {
            setOf(RiskSignal.MALICIOUS_IME)
        }
    }

    /**
     * Package of the IME that actually receives keystrokes, or `null` when it
     * cannot be determined (treated as "not observed" so a transient read never
     * fires the signal).
     *
     * Prefers the explicitly-selected default IME. When the platform exposes no
     * default but exactly one IME is enabled, that lone keyboard is
     * unambiguously the active one; with more than one enabled and no default we
     * cannot tell which is active and conservatively report nothing.
     */
    private fun activeImePackage(): String? {
        packageOf(env.defaultInputMethodId())?.let { return it }
        return env.enabledInputMethodIds()
            .mapNotNull { packageOf(it) }
            .distinct()
            .singleOrNull()
    }

    /**
     * Extracts the package from an input-method id. IME ids are flattened
     * `ComponentName`s (`"package/.Service"`); be defensive about a bare package
     * with no class and about blank/whitespace input.
     */
    private fun packageOf(imeId: String?): String? {
        val id = imeId?.trim().orEmpty()
        if (id.isEmpty()) return null
        return id.substringBefore('/').trim().ifEmpty { null }
    }

    private fun isTrustedKeyboard(pkg: String): Boolean {
        val normalized = pkg.lowercase()
        if (normalized in TRUSTED_IME_PACKAGES) return true
        return TRUSTED_IME_PREFIXES.any { normalized.startsWith(it) }
    }

    private companion object {
        /**
         * Well-known keyboards trusted by exact package name. Kept lowercase for
         * case-insensitive matching against the reported id.
         */
        val TRUSTED_IME_PACKAGES: Set<String> = hashSetOf(
            "com.google.android.inputmethod.latin", // Gboard
            "com.android.inputmethod.latin", // AOSP stock keyboard
            "com.touchtype.swiftkey", // Microsoft SwiftKey
            "com.touchtype.swiftkey.beta",
            "com.samsung.android.honeyboard", // Samsung stock (Honeyboard)
            "com.sec.android.inputmethod", // Samsung legacy keyboard
            "com.syntellia.fleksy.kb", // Fleksy
            "com.grammarly.android.keyboard", // Grammarly Keyboard
            "com.adamrocker.android.input.simeji", // Simeji
            "ru.yandex.androidkeyboard", // Yandex Keyboard
            "com.sonyericsson.textinput.uxp", // Sony stock keyboard
            "com.lge.ime", // LG stock keyboard
            "com.nuance.swype.dtc", // Swype (OEM-bundled)
        )

        /**
         * Platform / Google / OEM input-method namespaces that ship stock
         * keyboards. Scoped to keyboard sub-namespaces (not whole vendor
         * namespaces) so the prefix match stays meaningful while still covering
         * the long tail of legitimate OEM keyboards we cannot enumerate by exact
         * name. Kept lowercase.
         */
        val TRUSTED_IME_PREFIXES: List<String> = listOf(
            "com.google.android.inputmethod.", // Gboard language variants
            "com.google.android.apps.inputmethod.", // Google language IMEs
            "com.android.inputmethod.", // AOSP IMEs
            "com.sec.android.inputmethod", // Samsung
            "com.samsung.android.honeyboard", // Samsung (suffixed variants)
            "com.huawei.ohos.inputmethod", // Huawei
            "com.huawei.inputmethod",
            "com.miui.securityinputmethod", // Xiaomi/MIUI
            "com.baidu.input_mi", // Xiaomi/MIUI bundled stock keyboard
            "com.oppo.inputmethod", // OPPO
            "com.coloros.inputmethod", // OPPO/Realme ColorOS
            "com.vivo.inputmethod", // vivo
            "com.motorola.inputmethod", // Motorola
            "com.sonyericsson.textinput", // Sony
            "com.transsion.inputmethod", // Transsion (Tecno/Infinix/itel)
        )
    }
}
