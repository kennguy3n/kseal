package io.kseal.sdk.probes

import io.kseal.sdk.RiskSignal
import org.junit.Assert.assertEquals
import org.junit.Test

class ImeDetectorTest {

    private fun signals(configure: FakeDeviceEnvironment.() -> Unit): Set<RiskSignal> =
        ImeDetector(FakeDeviceEnvironment().apply(configure)).evaluate()

    // --- Trusted active keyboards: no signal ---------------------------------

    @Test
    fun defaultGboardIsClean() {
        // FakeDeviceEnvironment already defaults to Gboard; assert the baseline.
        assertEquals(emptySet<RiskSignal>(), ImeDetector(FakeDeviceEnvironment()).evaluate())
    }

    @Test
    fun aospStockKeyboardIsClean() {
        val s = signals { defaultInputMethod = "com.android.inputmethod.latin/.LatinIME" }
        assertEquals(emptySet<RiskSignal>(), s)
    }

    @Test
    fun swiftKeyIsClean() {
        val s = signals { defaultInputMethod = "com.touchtype.swiftkey/com.touchtype.KeyboardService" }
        assertEquals(emptySet<RiskSignal>(), s)
    }

    @Test
    fun oemStockKeyboardNamespaceIsClean() {
        // Samsung Honeyboard — covered by exact allowlist + prefix.
        val s = signals { defaultInputMethod = "com.samsung.android.honeyboard/.service.HoneyBoardService" }
        assertEquals(emptySet<RiskSignal>(), s)
    }

    @Test
    fun googleLanguageImeNamespaceIsClean() {
        // Google Pinyin IME — matched via the trusted namespace prefix.
        val s = signals { defaultInputMethod = "com.google.android.apps.inputmethod.pinyin/.PinyinIME" }
        assertEquals(emptySet<RiskSignal>(), s)
    }

    @Test
    fun trustedPackageMatchIsCaseInsensitive() {
        val s = signals { defaultInputMethod = "COM.GOOGLE.ANDROID.INPUTMETHOD.LATIN/.LatinIME" }
        assertEquals(emptySet<RiskSignal>(), s)
    }

    // --- Untrusted active keyboards: MALICIOUS_IME ---------------------------

    @Test
    fun sideLoadedThirdPartyKeyboardIsMalicious() {
        val s = signals { defaultInputMethod = "com.evil.keylogger/.SpyKeyboardService" }
        assertEquals(setOf(RiskSignal.MALICIOUS_IME), s)
    }

    @Test
    fun thirdPartyKeyboardWithAbsoluteClassIsMalicious() {
        val s = signals { defaultInputMethod = "net.shadykbd.app/net.shadykbd.app.ImeService" }
        assertEquals(setOf(RiskSignal.MALICIOUS_IME), s)
    }

    @Test
    fun bareUntrustedPackageWithoutClassIsMalicious() {
        // Defensive: an id with no component class still resolves a package.
        val s = signals { defaultInputMethod = "com.evil.keylogger" }
        assertEquals(setOf(RiskSignal.MALICIOUS_IME), s)
    }

    @Test
    fun lookAlikePackageOutsideTrustedNamespaceIsMalicious() {
        // Not under any allow-listed namespace, despite a Google-ish suffix.
        val s = signals { defaultInputMethod = "com.attacker.inputmethod.latin/.Fake" }
        assertEquals(setOf(RiskSignal.MALICIOUS_IME), s)
    }

    // --- Undeterminable active IME: conservative no-op -----------------------

    @Test
    fun nullDefaultIsClean() {
        val s = signals {
            defaultInputMethod = null
            inputMethodIds = emptyList()
        }
        assertEquals(emptySet<RiskSignal>(), s)
    }

    @Test
    fun blankDefaultIsClean() {
        val s = signals {
            defaultInputMethod = "   "
            inputMethodIds = emptyList()
        }
        assertEquals(emptySet<RiskSignal>(), s)
    }

    @Test
    fun noDefaultButMultipleEnabledIsAmbiguousAndClean() {
        // Cannot tell which enabled IME is active -> report nothing even though
        // one of them is third-party.
        val s = signals {
            defaultInputMethod = null
            inputMethodIds = listOf(
                "com.google.android.inputmethod.latin/.LatinIME",
                "com.evil.keylogger/.SpyKeyboardService",
            )
        }
        assertEquals(emptySet<RiskSignal>(), s)
    }

    // --- Active-IME-only scoping: enabled list does not over-fire ------------

    @Test
    fun noDefaultButSingleEnabledThirdPartyIsMalicious() {
        val s = signals {
            defaultInputMethod = null
            inputMethodIds = listOf("com.evil.keylogger/.SpyKeyboardService")
        }
        assertEquals(setOf(RiskSignal.MALICIOUS_IME), s)
    }

    @Test
    fun noDefaultButSingleEnabledTrustedIsClean() {
        val s = signals {
            defaultInputMethod = null
            inputMethodIds = listOf("com.google.android.inputmethod.latin/.LatinIME")
        }
        assertEquals(emptySet<RiskSignal>(), s)
    }

    @Test
    fun trustedDefaultWithEnabledThirdPartyDoesNotFire() {
        // Only the active keyboard is scored: an installed-but-inactive
        // third-party IME must not raise the signal.
        val s = signals {
            defaultInputMethod = "com.google.android.inputmethod.latin/.LatinIME"
            inputMethodIds = listOf(
                "com.google.android.inputmethod.latin/.LatinIME",
                "com.evil.keylogger/.SpyKeyboardService",
            )
        }
        assertEquals(emptySet<RiskSignal>(), s)
    }
}
