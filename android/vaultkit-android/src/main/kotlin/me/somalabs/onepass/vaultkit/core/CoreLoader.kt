package me.somalabs.onepass.vaultkit.core

import me.somalabs.onepass.core.uniffiEnsureInitialized

/**
 * Loads libonepass_ffi once, before any call into the core.
 *
 * The UniFFI bindings would load it lazily on the first call; loading it up
 * front makes a missing library, or one built from another version of
 * onepass-ffi (UniFFI contract and checksum checks), fail at launch rather
 * than in the middle of an operation. On Android JNA finds the library in
 * the APK's jniLibs; in the JVM tests, under `jna.library.path`.
 */
object CoreLoader {
    private val loaded: Unit by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        uniffiEnsureInitialized()
    }

    /** Idempotent and thread safe; throws if the library cannot be loaded. */
    fun ensureLoaded() {
        loaded
    }
}
