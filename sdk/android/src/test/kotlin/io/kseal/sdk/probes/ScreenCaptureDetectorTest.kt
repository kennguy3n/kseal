package io.kseal.sdk.probes

import io.kseal.sdk.RiskSignal
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Exercises the screen-capture detection rule directly (no Android framework):
 * the decision logic lives in pure functions on [ScreenCapturePolicy] so it is
 * deterministic on the JVM. The `Activity`/`DisplayManager` plumbing is only a
 * thin adapter that feeds these functions on a real device.
 */
class ScreenCaptureDetectorTest {

    private fun display(
        id: Int,
        isOn: Boolean = true,
        isSecure: Boolean = false,
        isPresentation: Boolean = false,
        isPrivate: Boolean = false,
    ) = DisplaySnapshot(
        displayId = id,
        isOn = isOn,
        isSecure = isSecure,
        isPresentation = isPresentation,
        isPrivate = isPrivate,
    )

    private val primary = display(ScreenCapturePolicy.DEFAULT_DISPLAY_ID)

    @Before
    fun reset() {
        ScreenCapturePolicy.clearScreenshotObservation()
    }

    @After
    fun tearDown() {
        ScreenCapturePolicy.clearScreenshotObservation()
    }

    @Test
    fun probeIdIsStable() {
        assertEquals("screen_capture", ScreenCaptureDetector().id)
    }

    @Test
    fun primaryDisplayOnlyIsClean() {
        assertTrue(ScreenCapturePolicy.assess(listOf(primary), screenshotObserved = false).isEmpty())
    }

    @Test
    fun noRegisteredActivityIsClean() {
        // Nothing registered + no screenshot ⇒ the probe observes nothing.
        assertTrue(ScreenCaptureDetector().evaluate().isEmpty())
    }

    @Test
    fun unprotectedSecondaryDisplayIsScreenCapture() {
        val displays = listOf(primary, display(id = 2, isSecure = false))
        val signals = ScreenCapturePolicy.assess(displays, screenshotObserved = false)
        assertTrue(RiskSignal.SCREEN_CAPTURE in signals)
    }

    @Test
    fun unprotectedPresentationDisplayIsScreenCapture() {
        val displays = listOf(primary, display(id = 3, isPresentation = true, isSecure = false))
        assertTrue(RiskSignal.SCREEN_CAPTURE in ScreenCapturePolicy.assess(displays, screenshotObserved = false))
    }

    @Test
    fun secureSecondaryDisplayIsClean() {
        // An HDCP-protected sink (e.g. a secure HDMI) cannot leak the UI.
        val displays = listOf(primary, display(id = 2, isSecure = true))
        assertTrue(ScreenCapturePolicy.assess(displays, screenshotObserved = false).isEmpty())
    }

    @Test
    fun poweredOffSecondaryDisplayIsClean() {
        val displays = listOf(primary, display(id = 2, isOn = false, isSecure = false))
        assertTrue(ScreenCapturePolicy.assess(displays, screenshotObserved = false).isEmpty())
    }

    @Test
    fun screenshotObservationIsScreenCapture() {
        assertEquals(
            setOf(RiskSignal.SCREEN_CAPTURE),
            ScreenCapturePolicy.assess(listOf(primary), screenshotObserved = true),
        )
    }

    @Test
    fun latchedScreenshotFlagsThroughDetector() {
        ScreenCapturePolicy.onScreenCaptured()
        assertTrue(RiskSignal.SCREEN_CAPTURE in ScreenCaptureDetector().evaluate())

        ScreenCapturePolicy.clearScreenshotObservation()
        assertTrue(ScreenCaptureDetector().evaluate().isEmpty())
    }

    @Test
    fun isUnprotectedMirrorSinkClassifiesEachDisplay() {
        assertFalse(ScreenCapturePolicy.isUnprotectedMirrorSink(primary))
        assertFalse(ScreenCapturePolicy.isUnprotectedMirrorSink(display(id = 2, isSecure = true)))
        assertFalse(ScreenCapturePolicy.isUnprotectedMirrorSink(display(id = 2, isOn = false)))
        assertTrue(ScreenCapturePolicy.isUnprotectedMirrorSink(display(id = 2)))
    }
}
