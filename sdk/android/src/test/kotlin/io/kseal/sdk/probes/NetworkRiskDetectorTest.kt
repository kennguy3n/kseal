package io.kseal.sdk.probes

import io.kseal.sdk.RiskSignal
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkRiskDetectorTest {

    @Test
    fun noProxyNoUserCaIsClean() {
        assertTrue(NetworkRiskDetector(FakeDeviceEnvironment()).evaluate().isEmpty())
    }

    @Test
    fun systemProxyIsProxyAndMitm() {
        val env = FakeDeviceEnvironment().apply { proxyHost = "10.0.2.2" }
        val signals = NetworkRiskDetector(env).evaluate()
        assertTrue(RiskSignal.PROXY in signals)
        assertTrue(RiskSignal.NETWORK_MITM in signals)
    }

    @Test
    fun userInstalledCaIsUserCaAndMitm() {
        val env = FakeDeviceEnvironment().apply { userCaCount = 2 }
        val signals = NetworkRiskDetector(env).evaluate()
        assertTrue(RiskSignal.USER_CA in signals)
        assertTrue(RiskSignal.NETWORK_MITM in signals)
    }
}
