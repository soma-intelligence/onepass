package me.somalabs.onepass.vault

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import me.somalabs.onepass.core.FfiDeviceKind
import me.somalabs.onepass.core.FfiDeviceMode
import me.somalabs.onepass.core.FfiStoreState
import me.somalabs.onepass.core.Session
import me.somalabs.onepass.core.createAccountV2
import me.somalabs.onepass.core.generateClassicalDeviceKeys
import me.somalabs.onepass.core.generateSoftwarePqHalf
import me.somalabs.onepass.core.newDeviceRngSeed
import me.somalabs.onepass.core.openSoftwarePqHalf
import me.somalabs.onepass.core.resetStore
import me.somalabs.onepass.core.setDeviceRngSeed
import me.somalabs.onepass.core.storeState
import me.somalabs.onepass.core.unlockWithPassword

/**
 * This device's vault (spec 2026-10-30 sections 6.1 and 6.2).
 *
 * The vault database lives in `noBackupFilesDir`. Beside it, `device.bin`
 * keeps what the core needs on this device besides the master password: the
 * Secret Key, the device keys (classical bytes and the software post-quantum
 * half) and the seed of the hedged random source. The file is sealed with
 * AES-256-GCM by a non-exportable Android Keystore key (StrongBox when the
 * device has one, else the TEE): copied to another device, it opens nowhere.
 *
 * Nothing here is logged. Secrets are wiped from the arrays that held them
 * as soon as the core has them.
 */
class DeviceVault private constructor(private val context: Context) {
    private val dir: File = context.noBackupFilesDir
    val dbPath: String get() = File(dir, "vault.db").absolutePath
    private val deviceFile: File get() = File(dir, "device.bin")

    @Volatile
    var session: Session? = null
        private set

    /** Where the hardware key lives (StrongBox, TEE), read from the key itself. */
    val protection: String
        get() {
            key()
            return protectionLabel
        }

    private var protectionLabel: String = "Android Keystore"

    /** Unix millis of the last use while unlocked, for the auto-lock. */
    @Volatile
    private var lastUse: Long = 0

    enum class State { EMPTY, LOCKED, UNLOCKED, NO_DEVICE_FILE, MISSING }

    fun state(): State {
        if (session != null) return State.UNLOCKED
        return when (storeState(dbPath)) {
            FfiStoreState.EMPTY -> State.EMPTY
            FfiStoreState.ACCOUNT -> if (deviceFile.exists()) State.LOCKED else State.NO_DEVICE_FILE
            FfiStoreState.PINNED_BUT_MISSING -> State.MISSING
        }
    }

    /** Creates the account; returns the Secret Key to show once. */
    fun create(password: CharArray, deviceName: String): String {
        val seed = newDeviceRngSeed()
        setDeviceRngSeed(seed)
        val classical = generateClassicalDeviceKeys()
        val pq = generateSoftwarePqHalf()
        val created = createAccountV2(
            dbPath, String(password), null, classical, openSoftwarePqHalf(pq),
            deviceName, FfiDeviceKind.ANDROID, FfiDeviceMode.PERSONAL,
        )
        try {
            write(Secrets(created.accountId, created.secretKey, classical, pq, seed))
        } catch (e: Exception) {
            created.session.lock()
            runCatching { resetStore(dbPath) }
            throw e
        } finally {
            classical.fill(0); pq.fill(0); seed.fill(0)
        }
        opened(created.session)
        return created.secretKey
    }

    fun unlock(password: CharArray) {
        val secrets = read() ?: error("no device file")
        try {
            setDeviceRngSeed(secrets.seed)
            val unlocked = unlockWithPassword(dbPath, String(password), secrets.secretKey)
            unlocked.auk.fill(0)
            opened(unlocked.session)
        } finally {
            secrets.wipe()
        }
    }

    fun lock() {
        session?.lock()
        session = null
    }

    fun touch() {
        lastUse = System.currentTimeMillis()
    }

    /** Locks if unused for [AUTO_LOCK_MS]. True when it locked. */
    fun lockIfIdle(): Boolean {
        if (session != null && System.currentTimeMillis() - lastUse >= AUTO_LOCK_MS) {
            lock()
            return true
        }
        return false
    }

    private fun opened(s: Session) {
        session = s
        touch()
    }

    // ---- device.bin ---------------------------------------------------------------

    private class Secrets(
        val accountId: String,
        val secretKey: String,
        val classical: ByteArray,
        val pq: ByteArray,
        val seed: ByteArray,
    ) {
        fun wipe() {
            classical.fill(0); pq.fill(0); seed.fill(0)
        }
    }

    private fun write(s: Secrets) {
        val plain = ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { out ->
                out.writeByte(1)
                out.writeUTF(s.accountId)
                out.writeUTF(s.secretKey)
                for (b in listOf(s.classical, s.pq, s.seed)) {
                    out.writeInt(b.size)
                    out.write(b)
                }
            }
            bytes.toByteArray()
        }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key())
        cipher.updateAAD(AAD)
        val sealed = cipher.doFinal(plain)
        plain.fill(0)
        val tmp = File(dir, "device.bin.tmp")
        tmp.outputStream().use { out ->
            out.write(cipher.iv.size)
            out.write(cipher.iv)
            out.write(sealed)
            out.fd.sync()
        }
        if (!tmp.renameTo(deviceFile)) error("cannot write the device file")
    }

    private fun read(): Secrets? {
        if (!deviceFile.exists()) return null
        val all = deviceFile.readBytes()
        val ivLen = all[0].toInt()
        val iv = all.copyOfRange(1, 1 + ivLen)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv))
        cipher.updateAAD(AAD)
        val plain = cipher.doFinal(all, 1 + ivLen, all.size - 1 - ivLen)
        try {
            DataInputStream(plain.inputStream()).use { input ->
                require(input.readByte().toInt() == 1) { "device file version" }
                val accountId = input.readUTF()
                val secretKey = input.readUTF()
                fun bytes(): ByteArray = ByteArray(input.readInt()).also { input.readFully(it) }
                return Secrets(accountId, secretKey, bytes(), bytes(), bytes())
            }
        } finally {
            plain.fill(0)
        }
    }

    /** The AES-256 Keystore key, made on first use. */
    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(KEY_ALIAS, null) as? SecretKey)?.let {
            protectionLabel = describe(it)
            return it
        }
        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(
            KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .setIsStrongBoxBacked(strongBox)
            .build()
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val key = try {
            generator.init(spec(true))
            generator.generateKey()
        } catch (_: StrongBoxUnavailableException) {
            generator.init(spec(false))
            generator.generateKey()
        }
        protectionLabel = describe(key)
        return key
    }

    private fun describe(key: SecretKey): String {
        val info = runCatching {
            javax.crypto.SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
                .getKeySpec(key, android.security.keystore.KeyInfo::class.java) as android.security.keystore.KeyInfo
        }.getOrNull() ?: return "Android Keystore"
        return if (Build.VERSION.SDK_INT >= 31) {
            when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> "StrongBox"
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TEE"
                else -> "Android Keystore (logiciel)"
            }
        } else {
            "Android Keystore"
        }
    }

    companion object {
        /** Five minutes unused, the app locks (also on return from the background). */
        const val AUTO_LOCK_MS = 5 * 60 * 1000L
        private const val KEY_ALIAS = "onepass.device.v1"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private val AAD = "onepass/android/device/v1".toByteArray()

        @Volatile
        private var instance: DeviceVault? = null

        fun get(context: Context): DeviceVault =
            instance ?: synchronized(this) {
                instance ?: DeviceVault(context.applicationContext).also { instance = it }
            }
    }
}
