package me.somalabs.onepass.vaultkit.core

import java.nio.file.Path
import me.somalabs.onepass.core.FfiKdfParams
import me.somalabs.onepass.core.FfiPasswordRecipe
import me.somalabs.onepass.core.OnePassException
import me.somalabs.onepass.core.createAccountWithKdfBytes
import me.somalabs.onepass.core.generatePassword
import me.somalabs.onepass.core.itemTypes
import me.somalabs.onepass.core.unlockWithPasswordBytes
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.io.TempDir

/**
 * The generated Kotlin bindings against the host build of onepass-ffi
 * (`cargo build -p onepass-ffi --features bindgen,dev-fast-kdf`, task
 * `:vaultkit-android:buildHostCore`), loaded by JNA
 * from `jna.library.path`.
 */
class CoreBindingsTest {
    companion object {
        /** The dev floor of the core (`DEV_KDF_FLOOR`): debug builds with `dev-fast-kdf` only. */
        private val FAST_KDF = FfiKdfParams(mKib = 8192u, t = 1u, p = 1u)

        @JvmStatic
        @BeforeAll
        fun loadCore() {
            CoreLoader.ensureLoaded()
        }
    }

    @TempDir
    lateinit var dir: Path

    private fun password(): ByteArray = "correct horse battery staple".toByteArray(Charsets.UTF_8)

    @Test
    fun generatesACharacterPasswordOfTheRequestedLength() {
        val generated =
            generatePassword(
                FfiPasswordRecipe.Characters(
                    length = 20u,
                    digits = true,
                    symbols = true,
                    avoidAmbiguous = false,
                ),
            )
        assertEquals(20, generated.length)
    }

    @Test
    fun createsAnAccountThenUnlocksItWithTheReturnedSecretKey() {
        val dbPath = dir.resolve("vault.db").toString()
        val created = createAccountWithKdfBytes(dbPath, password(), FAST_KDF)
        created.session.close()
        val secretKey = created.secretKey.toByteArray(Charsets.UTF_8)
        try {
            val unlocked = unlockWithPasswordBytes(dbPath, password(), secretKey.copyOf())
            unlocked.session.use { _ ->
                assertEquals(32, unlocked.auk.size)
                unlocked.auk.fill(0)
            }
        } finally {
            secretKey.fill(0)
        }
    }

    @Test
    fun listsTheTwentySixItemTypes() {
        assertEquals(26, itemTypes().size)
    }

    @Test
    fun aWrongPasswordRaisesTheTypedError() {
        val dbPath = dir.resolve("vault.db").toString()
        val created = createAccountWithKdfBytes(dbPath, password(), FAST_KDF)
        created.session.close()
        val secretKey = created.secretKey.toByteArray(Charsets.UTF_8)
        try {
            // The typed subclass of the generated OnePassException.
            assertThrows<OnePassException.WrongPassword> {
                unlockWithPasswordBytes(dbPath, "wrong".toByteArray(Charsets.UTF_8), secretKey.copyOf())
            }
        } finally {
            secretKey.fill(0)
        }
    }
}
