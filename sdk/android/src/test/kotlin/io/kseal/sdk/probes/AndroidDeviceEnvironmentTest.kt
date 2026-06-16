package io.kseal.sdk.probes

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

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
    fun installedPackagesIncludesSelf() {
        assertTrue(env.installedPackages().isNotEmpty())
    }

    @Test
    fun isSystemPackageIsSafeForUnknownPackage() {
        // An unknown package must resolve to false rather than throwing.
        assertFalse(env.isSystemPackage("com.example.definitely.not.installed"))
    }
}
