package io.kseal.sdk.probes

import io.kseal.sdk.RiskSignal

/**
 * A single RASP probe. Probes are pure detectors: they read the device
 * environment and return the set of [RiskSignal]s they observe. They perform no
 * I/O at construction (probes are cheap to create and run lazily/on demand) and
 * never throw — a probe that cannot complete a check treats it as "not
 * observed" so a transient failure can never crash the host app.
 */
interface Probe {
    /** Stable identifier (used for logging and selective enablement). */
    val id: String

    /** Runs the probe and returns the detected signals (empty when clean). */
    fun evaluate(): Set<RiskSignal>
}
