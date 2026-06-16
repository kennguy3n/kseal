package io.kseal.sdk.probes

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Context
import android.hardware.display.DisplayManager
import android.os.Build
import android.view.Display
import android.view.WindowManager
import androidx.annotation.RequiresApi
import io.kseal.sdk.RiskSignal
import java.lang.ref.WeakReference
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Detects when the app's UI is being captured, recorded, or mirrored — a
 * credential/OTP exfiltration vector ([RiskSignal.SCREEN_CAPTURE]).
 *
 * The probe is constructed with no [DeviceEnvironment] because Android exposes
 * no global "is the screen being recorded" flag the way iOS does: live capture
 * is window/`Activity`-scoped. Two synchronously-queryable signals are fused:
 *
 *  1. **Display mirroring** — at probe time we enumerate every logical display
 *     via [DisplayManager] and flag an unprotected secondary display (an
 *     external/cast/virtual sink that is powered on and lacks a secure HDCP
 *     output). The primary UI, including OTP fields, can be read off such a
 *     sink. See [ScreenCapturePolicy.isUnprotectedMirrorSink] for the rule.
 *  2. **Screenshots** — on API 34+ the host can register its foreground
 *     `Activity` (see [ScreenCapturePolicy.registerActivity]) so an
 *     `Activity.ScreenCaptureCallback` latches a screenshot observation.
 *
 * Display enumeration needs a [Context], and screenshot/`FLAG_SECURE` control
 * needs the foreground `Activity` — neither is available to a probe the SDK
 * builds with no arguments. [ScreenCapturePolicy] is the self-contained,
 * host-facing API the app calls from its `Activity` lifecycle; until it is
 * wired up the probe degrades to "nothing observed" (it never throws).
 */
internal class ScreenCaptureDetector : Probe {

    override val id: String = "screen_capture"

    override fun evaluate(): Set<RiskSignal> = ScreenCapturePolicy.evaluate()
}

/** Immutable snapshot of one logical display, captured at probe time. */
internal data class DisplaySnapshot(
    val displayId: Int,
    val isOn: Boolean,
    val isSecure: Boolean,
    val isPresentation: Boolean,
    val isPrivate: Boolean,
)

/**
 * Host-facing API for the screen-capture probe (the SDK never wires this up).
 *
 * The integrating app calls [registerActivity]/[unregisterActivity] from its
 * foreground `Activity`'s `onStart`/`onStop` so the probe can (a) enumerate
 * displays through a live [Context] and (b) on API 34+ observe screenshots via
 * `Activity.ScreenCaptureCallback`. Screenshot observation requires the host to
 * declare `android.permission.DETECT_SCREEN_CAPTURE` in its manifest.
 *
 * [applySecureFlag] is the actual mitigation: `WindowManager.LayoutParams
 * .FLAG_SECURE` makes the OS render a blank frame on recordings, screenshots,
 * and non-secure mirror sinks. The detector only *reports* the risk; enforcing
 * it is the host's policy choice, exposed here so both live in one place.
 *
 * **False positives:** an unprotected secondary display cannot be told apart
 * from a benign one (a wired HDMI monitor, a Chromecast "Cast screen", a
 * presentation projector) using only public, non-blocking APIs. We err toward
 * reporting — an attacker mirroring to read an OTP looks identical to a user
 * casting their screen — and leave the disposition to the server-side policy
 * engine (e.g. step-up rather than block) rather than guessing on-device.
 */
object ScreenCapturePolicy {

    /** Mirrors `android.view.Display.DEFAULT_DISPLAY`; kept local so the pure
     * detection rule has no Android-framework dependency in unit tests. */
    internal const val DEFAULT_DISPLAY_ID: Int = 0

    private val screenshotObserved = AtomicBoolean(false)
    private val secureFlagApplied = AtomicBoolean(false)

    @Volatile
    private var contextRef: WeakReference<Context>? = null

    @Volatile
    private var activityRef: WeakReference<Activity>? = null

    // Held as Any? so the API-34 `Activity.ScreenCaptureCallback` type is only
    // touched inside an explicit SDK_INT guard.
    @Volatile
    private var screenCaptureCallback: Any? = null

    /**
     * Registers the current foreground [activity]. Call from `Activity.onStart`.
     * Stores the application [Context] for display enumeration and, on API 34+,
     * registers an `Activity.ScreenCaptureCallback` to latch screenshots.
     */
    fun registerActivity(activity: Activity) {
        // Release any callback still registered on a previously-registered
        // Activity first: re-registering without a matching unregisterActivity
        // (e.g. two Activities registering concurrently) would otherwise orphan
        // the earlier Activity's ScreenCaptureCallback.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            activityRef?.get()?.let { unregisterScreenCaptureCallback(it) }
        }
        screenCaptureCallback = null
        activityRef = WeakReference(activity)
        contextRef = WeakReference(activity.applicationContext)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            registerScreenCaptureCallback(activity)
        }
    }

    /**
     * Releases the [activity] registered via [registerActivity]. Call from
     * `Activity.onStop` to avoid leaking the window and to stop screenshot
     * observation.
     */
    fun unregisterActivity(activity: Activity) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            unregisterScreenCaptureCallback(activity)
        }
        screenCaptureCallback = null
        activityRef = null
        contextRef = null
    }

    /**
     * Applies (or clears) `FLAG_SECURE` on the [activity]'s window. When set the
     * OS blanks the window on screenshots, recordings, and non-secure mirror
     * displays — the real defense the [ScreenCaptureDetector] signal motivates.
     */
    fun applySecureFlag(activity: Activity, secure: Boolean) {
        runCatching {
            val window = activity.window ?: return
            if (secure) {
                window.setFlags(
                    WindowManager.LayoutParams.FLAG_SECURE,
                    WindowManager.LayoutParams.FLAG_SECURE,
                )
            } else {
                window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
            }
            secureFlagApplied.set(secure)
        }
    }

    /** Whether the host last set `FLAG_SECURE` via [applySecureFlag]. */
    fun isSecureFlagApplied(): Boolean = secureFlagApplied.get()

    /** Clears a latched screenshot observation (e.g. after the host reacts). */
    fun clearScreenshotObservation() {
        screenshotObserved.set(false)
    }

    /**
     * Resets all host-supplied state: unregisters any API-34 screenshot
     * callback, drops the stored `Activity`/`Context`, and clears the latched
     * screenshot observation and `FLAG_SECURE` record.
     *
     * [ScreenCapturePolicy] is a process-level singleton the SDK never wires up,
     * so its state would otherwise outlive a `KsealSDK.shutdown()` and leak into
     * a subsequent re-init (or across tests). The host should call this from its
     * shutdown path; the SDK deliberately does not reach into this object.
     */
    fun reset() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            activityRef?.get()?.let { unregisterScreenCaptureCallback(it) }
        }
        screenCaptureCallback = null
        activityRef = null
        contextRef = null
        screenshotObserved.set(false)
        secureFlagApplied.set(false)
    }

    /** Runs the fused detection; never throws (a failure means "not observed"). */
    internal fun evaluate(): Set<RiskSignal> = runCatching {
        assess(displaySnapshots(), screenshotObserved.get())
    }.getOrDefault(emptySet())

    /**
     * Pure detection rule over a [displays] snapshot plus whether a screenshot
     * was observed. A latched screenshot or any unprotected mirror sink yields
     * [RiskSignal.SCREEN_CAPTURE].
     */
    internal fun assess(displays: List<DisplaySnapshot>, screenshotObserved: Boolean): Set<RiskSignal> {
        val captured = screenshotObserved || displays.any(::isUnprotectedMirrorSink)
        return if (captured) setOf(RiskSignal.SCREEN_CAPTURE) else emptySet()
    }

    /**
     * A secondary display ([DisplaySnapshot.displayId] != [DEFAULT_DISPLAY_ID])
     * that is powered on and lacks a secure (HDCP-protected) output is treated
     * as an active capture/mirror sink: the primary UI can be read off it. The
     * built-in primary display and secure secondary displays are ignored.
     */
    internal fun isUnprotectedMirrorSink(display: DisplaySnapshot): Boolean =
        display.displayId != DEFAULT_DISPLAY_ID && display.isOn && !display.isSecure

    /** Called by the API-34 screenshot callback; latches an observation. */
    internal fun onScreenCaptured() {
        screenshotObserved.set(true)
    }

    private fun displaySnapshots(): List<DisplaySnapshot> {
        val context = contextRef?.get() ?: return emptyList()
        val manager = context.getSystemService(Context.DISPLAY_SERVICE) as? DisplayManager
            ?: return emptyList()
        return manager.displays.orEmpty().map { it.toSnapshot() }
    }

    /**
     * Treats every display state except [Display.STATE_OFF] as powered on.
     * A MediaProjection/virtual recording display can report
     * [Display.STATE_UNKNOWN] (and external sinks may report `DOZE`/`VR`/
     * `ON_SUSPEND`) instead of [Display.STATE_ON]; matching only `STATE_ON`
     * would miss those captures, so we cast the wider net and let the
     * `displayId`/secure-flag checks in [isUnprotectedMirrorSink] gate the rest.
     */
    internal fun isDisplayPoweredOn(state: Int): Boolean = state != Display.STATE_OFF

    private fun Display.toSnapshot(): DisplaySnapshot = DisplaySnapshot(
        displayId = displayId,
        isOn = isDisplayPoweredOn(state),
        isSecure = (flags and Display.FLAG_SECURE) != 0,
        isPresentation = (flags and Display.FLAG_PRESENTATION) != 0,
        isPrivate = (flags and Display.FLAG_PRIVATE) != 0,
    )

    @RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @SuppressLint("MissingPermission") // host declares android.permission.DETECT_SCREEN_CAPTURE
    private fun registerScreenCaptureCallback(activity: Activity) {
        runCatching {
            val callback = Activity.ScreenCaptureCallback { onScreenCaptured() }
            activity.registerScreenCaptureCallback(activity.mainExecutor, callback)
            screenCaptureCallback = callback
        }
    }

    @RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @SuppressLint("MissingPermission") // host declares android.permission.DETECT_SCREEN_CAPTURE
    private fun unregisterScreenCaptureCallback(activity: Activity) {
        val callback = screenCaptureCallback as? Activity.ScreenCaptureCallback ?: return
        runCatching { activity.unregisterScreenCaptureCallback(callback) }
    }
}
