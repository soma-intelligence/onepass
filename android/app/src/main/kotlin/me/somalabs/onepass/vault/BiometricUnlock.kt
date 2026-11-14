package me.somalabs.onepass.vault

import android.app.Activity
import android.content.Context
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Fingerprint or face unlock (iPhone: Face ID, `BiometricUnlock`).
 *
 * The Account Unlock Key is wrapped with AES-256-GCM by an Android Keystore
 * key that only works right after a strong biometric check
 * (setUserAuthenticationRequired, one use per check) and that the system
 * invalidates when a fingerprint or face is added. The wrapped key, the date
 * of the last master password and the boot count live in
 * `noBackupFilesDir/biometric.bin`.
 *
 * Same policy as iOS: the master password is asked again every 14 days, after
 * a restart and when the enrolled biometrics change; those drop the
 * enrollment. A cancel or a failed match keeps it.
 */
class BiometricUnlock(private val context: Context) {
    private val file get() = File(context.noBackupFilesDir, "biometric.bin")

    enum class Availability { AVAILABLE, NOT_ENROLLED, NO_HARDWARE }

    sealed class Outcome {
        class Unlocked(val auk: ByteArray) : Outcome()
        object Cancelled : Outcome()
        /** The password is needed; `message` says why (null: say nothing). */
        class PasswordRequired(val message: Reason) : Outcome()
    }

    enum class Reason { NOT_ENROLLED, EXPIRED, REBOOTED, INVALIDATED, LOCKED_OUT, FAILED }

    private class Enrollment(val iv: ByteArray, val wrapped: ByteArray, val lastPasswordAt: Long, val bootCount: Int)

    fun availability(): Availability {
        val bm = context.getSystemService(BiometricManager::class.java) ?: return Availability.NO_HARDWARE
        val r = if (Build.VERSION.SDK_INT >= 30) bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        else @Suppress("DEPRECATION") bm.canAuthenticate()
        return when (r) {
            BiometricManager.BIOMETRIC_SUCCESS -> Availability.AVAILABLE
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> Availability.NOT_ENROLLED
            else -> Availability.NO_HARDWARE
        }
    }

    val enrolled: Boolean get() = file.exists()

    /** When the master password is asked again, null when not enrolled. */
    fun passwordDueAt(): Long? = load()?.let { it.lastPasswordAt + PASSWORD_EVERY_MS }

    private fun bootCount(): Int = runCatching { Settings.Global.getInt(context.contentResolver, Settings.Global.BOOT_COUNT) }.getOrDefault(-1)

    // ---- enroll --------------------------------------------------------------------------------

    /**
     * Wraps [auk] after one biometric check. [done] gets null on success, or
     * the reason it failed ("cancelled" is [Reason.FAILED] with cancelled = true).
     */
    fun enroll(activity: Activity, title: String, subtitle: String, cancel: String, auk: ByteArray, done: (ok: Boolean, error: CharSequence?) -> Unit) {
        val cipher = try {
            deleteKey()
            Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, createKey()) }
        } catch (e: Exception) {
            auk.fill(0)
            return done(false, e.javaClass.simpleName)
        }
        prompt(activity, title, subtitle, cancel, cipher) { result, error ->
            if (result == null) {
                auk.fill(0)
                return@prompt done(false, error)
            }
            try {
                result.updateAAD(AAD)
                val wrapped = result.doFinal(auk)
                save(Enrollment(result.iv, wrapped, System.currentTimeMillis(), bootCount()))
                done(true, null)
            } catch (e: Exception) {
                disable()
                done(false, e.javaClass.simpleName)
            } finally {
                auk.fill(0)
            }
        }
    }

    /** After every master password unlock: the 14 days start again, and a reboot is forgiven. */
    fun notePasswordUnlock() {
        val e = load() ?: return
        save(Enrollment(e.iv, e.wrapped, System.currentTimeMillis(), bootCount()))
    }

    fun disable() {
        file.delete()
        runCatching { deleteKey() }
    }

    // ---- unlock --------------------------------------------------------------------------------

    fun unlock(activity: Activity, title: String, subtitle: String, cancel: String, done: (Outcome) -> Unit) {
        val e = load() ?: return done(Outcome.PasswordRequired(Reason.NOT_ENROLLED))
        val now = System.currentTimeMillis()
        val boot = bootCount()
        if (boot != -1 && e.bootCount != -1 && boot != e.bootCount) {
            disable()
            return done(Outcome.PasswordRequired(Reason.REBOOTED))
        }
        if (now - e.lastPasswordAt > PASSWORD_EVERY_MS || e.lastPasswordAt - now > CLOCK_SKEW_MS) {
            disable()
            return done(Outcome.PasswordRequired(Reason.EXPIRED))
        }
        val cipher = try {
            val key = existingKey() ?: run { disable(); return done(Outcome.PasswordRequired(Reason.INVALIDATED)) }
            Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, e.iv)) }
        } catch (_: KeyPermanentlyInvalidatedException) {
            disable()
            return done(Outcome.PasswordRequired(Reason.INVALIDATED))
        } catch (_: Exception) {
            return done(Outcome.PasswordRequired(Reason.FAILED))
        }
        prompt(activity, title, subtitle, cancel, cipher) { result, error ->
            if (result == null) {
                return@prompt done(if (error == null) Outcome.Cancelled else if (lockedOut) Outcome.PasswordRequired(Reason.LOCKED_OUT) else Outcome.PasswordRequired(Reason.FAILED))
            }
            try {
                result.updateAAD(AAD)
                done(Outcome.Unlocked(result.doFinal(e.wrapped)))
            } catch (_: Exception) {
                done(Outcome.PasswordRequired(Reason.FAILED))
            }
        }
    }

    private var lockedOut = false

    /** The system sheet: [done] gets the unlocked cipher, or null and an error (null error: cancelled). */
    private fun prompt(activity: Activity, title: String, subtitle: String, cancel: String, cipher: Cipher, done: (Cipher?, CharSequence?) -> Unit) {
        lockedOut = false
        val exec = activity.mainExecutor
        val b = BiometricPrompt.Builder(activity).setTitle(title).setSubtitle(subtitle)
            .setNegativeButton(cancel, exec) { _, _ -> done(null, null) }
        if (Build.VERSION.SDK_INT >= 30) b.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        val signal = CancellationSignal()
        b.build().authenticate(BiometricPrompt.CryptoObject(cipher), signal, exec, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                done(result.cryptoObject?.cipher, if (result.cryptoObject?.cipher == null) "no cipher" else null)
            }

            override fun onAuthenticationError(code: Int, msg: CharSequence) {
                val cancelled = code == BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED || code == BiometricPrompt.BIOMETRIC_ERROR_CANCELED
                lockedOut = code == BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT || code == BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT_PERMANENT
                done(null, if (cancelled) null else msg)
            }
        })
    }

    // ---- storage -------------------------------------------------------------------------------

    private fun save(e: Enrollment) {
        val bytes = ByteArrayOutputStream().use { b ->
            DataOutputStream(b).use { out ->
                out.writeByte(1)
                out.writeInt(e.iv.size); out.write(e.iv)
                out.writeInt(e.wrapped.size); out.write(e.wrapped)
                out.writeLong(e.lastPasswordAt)
                out.writeInt(e.bootCount)
            }
            b.toByteArray()
        }
        val tmp = File(file.parentFile, "biometric.bin.tmp")
        tmp.writeBytes(bytes)
        if (!tmp.renameTo(file)) error("cannot write the biometric file")
    }

    private fun load(): Enrollment? = runCatching {
        if (!file.exists()) return null
        DataInputStream(file.inputStream()).use { input ->
            require(input.readByte().toInt() == 1)
            fun bytes() = ByteArray(input.readInt().also { require(it in 1..4096) }).also { input.readFully(it) }
            Enrollment(bytes(), bytes(), input.readLong(), input.readInt())
        }
    }.getOrElse { file.delete(); null }

    private fun keyStore() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun existingKey(): SecretKey? = keyStore().getKey(KEY_ALIAS, null) as? SecretKey

    private fun deleteKey() {
        val ks = keyStore()
        if (ks.containsAlias(KEY_ALIAS)) ks.deleteEntry(KEY_ALIAS)
    }

    private fun createKey(): SecretKey {
        val spec = KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .apply {
                if (Build.VERSION.SDK_INT >= 30) setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                else @Suppress("DEPRECATION") setUserAuthenticationValidityDurationSeconds(-1)
            }
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run { init(spec); generateKey() }
    }

    companion object {
        const val PASSWORD_EVERY_MS = 14L * 86_400_000
        private const val CLOCK_SKEW_MS = 300_000L
        private const val KEY_ALIAS = "onepass.biometric.v1"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private val AAD = "onepass/android/biometric/v1".toByteArray()
    }
}
