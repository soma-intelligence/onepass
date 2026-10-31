package me.somalabs.onepass

import android.app.Activity
import android.os.Bundle
import me.somalabs.onepass.vaultkit.core.CoreLoader

/** Empty screen for now; loads the Rust core at launch so a broken .so fails here. */
class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        CoreLoader.ensureLoaded()
    }
}
