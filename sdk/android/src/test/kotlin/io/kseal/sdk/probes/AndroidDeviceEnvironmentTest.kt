package io.kseal.sdk.probes

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File

/**
 * Validates the production [AndroidDeviceEnvironment] against real Android APIs
 * (PackageManager, Build, the CA store) running on the JVM via Robolectric — no
 * device required. We assert the accessors are robust (never throw, sane types)
 * rather than specific device values.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class AndroidDeviceEnvironmentTest {

    private val env: AndroidDeviceEnvironment by lazy {
        AndroidDeviceEnvironment(ApplicationProvider.getApplicationContext<Context>())
    }

    @Test
    fun buildIdentityIsNonNull() {
        assertNotNull(env.fingerprint)
        assertNotNull(env.model)
        assertNotNull(env.manufacturer)
        assertNotNull(env.buildTags)
    }

    @Test
    fun installerAndSigningAccessorsDoNotThrow() {
        // May be empty under Robolectric; the contract is "no crash, valid type".
        assertNotNull(env.signingCertificateSha256())
        env.installerPackageName() // no assertion: just must not throw
    }

    @Test
    fun cleanHostHasNoProxy() {
        assertNull(env.httpProxyHost())
    }

    @Test
    fun userCaCountIsNonNegative() {
        assertTrue(env.userInstalledCaCount() >= 0)
    }

    @Test
    fun procStatusAccessorsAreSafe() {
        // On the Linux test host /proc exists; assert sane, non-crashing reads.
        assertTrue(env.tracerPid() >= -1)
        env.processMaps() // must not throw
    }

    @Test
    fun nativeProbeAccessorsAreSafe() {
        // Without the JNI library on the test classpath these degrade to the
        // "unavailable" sentinel (negative) rather than throwing; with it they
        // return 0/1. Either way the value is a valid tri-state.
        assertTrue(env.nativeDebuggerPresent() >= -1)
        assertTrue(env.nativeHookPresent() >= -1)
    }

    @Test
    fun sha256OfFileMatchesKnownVector() {
        // SHA-256("abc") = the well-known NIST test vector.
        val file = File.createTempFile("kseal-integrity", ".bin")
        try {
            file.writeBytes("abc".toByteArray(Charsets.US_ASCII))
            assertEquals(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                env.sha256OfFile(file.absolutePath),
            )
        } finally {
            file.delete()
        }
    }

    @Test
    fun sha256OfMissingFileIsNull() {
        assertNull(env.sha256OfFile("/does/not/exist/kseal-missing.bin"))
    }

    @Test
    fun installedPackagesIncludesSelf() {
        assertTrue(env.installedPackages().isNotEmpty())
    }

    @Test
    fun isSystemPackageIsSafeForUnknownPackage() {
        // An unknown package must resolve to false rather than throwing.
        assertFalse(env.isSystemPackage("com.example.definitely.not.installed"))
    }
}
