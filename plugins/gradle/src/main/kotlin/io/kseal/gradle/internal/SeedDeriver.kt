package io.kseal.gradle.internal

/**
 * Derives the per-build polymorphism seed.
 *
 * The security goal is that a bypass crafted against one shipped build does not
 * transfer to the next: every distinct build gets an independent seed from which
 * all transform keys and layout permutations are derived. The performance goal is
 * that the seed be a pure function of the build's inputs, so two byte-identical
 * builds derive the same seed and the hardening tasks stay cacheable / `UP-TO-DATE`.
 *
 * Resolution order:
 *  1. [explicitSeedHex] — a caller-pinned seed (fully reproducible builds / tests).
 *  2. [randomize] — a fresh random seed every build (max polymorphism, not cacheable).
 *  3. otherwise — `HKDF(ikm = masterKey or inputsDigest, salt = project salt,
 *     info = inputsDigest)`. With a per-tenant [masterKeyHex] the seed is
 *     unpredictable to an attacker yet deterministic for identical inputs; without
 *     one it degrades to a content-derived seed (lower assurance — see docs).
 */
internal object SeedDeriver {

    data class Inputs(
        val explicitSeedHex: String?,
        val randomize: Boolean,
        val masterKeyHex: String?,
        val projectSalt: String,
        val inputsDigestHex: String,
    )

    fun derive(inputs: Inputs): ByteArray {
        inputs.explicitSeedHex?.takeIf { it.isNotBlank() }?.let { hexSeed ->
            val seed = Crypto.unhex(hexSeed.trim())
            require(seed.size == Crypto.SEED_BYTES) {
                "kseal polymorphism seed must be ${Crypto.SEED_BYTES} bytes (${Crypto.SEED_BYTES * 2} hex chars)"
            }
            return seed
        }
        if (inputs.randomize) return Crypto.randomSeed()

        val digest = Crypto.unhex(inputs.inputsDigestHex)
        val masterKey = inputs.masterKeyHex?.takeIf { it.isNotBlank() }?.let { Crypto.unhex(it.trim()) }
        val ikm = masterKey ?: digest
        return Crypto.hkdf(
            ikm = ikm,
            salt = inputs.projectSalt.toByteArray(),
            info = digest,
            length = Crypto.SEED_BYTES,
        )
    }
}
