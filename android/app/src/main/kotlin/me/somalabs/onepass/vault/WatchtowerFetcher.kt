package me.somalabs.onepass.vault

import android.content.Context
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.net.ssl.HttpsURLConnection
import me.somalabs.onepass.core.FfiRangeResponse

/**
 * The public data Watchtower downloads when "Vérifier les fuites" is on
 * (iPhone: `WatchtowerFetcher`). The core makes no network call: it lists the
 * SHA-1 prefixes it could not look up (5 hex characters per distinct
 * password), these ranges come from Have I Been Pwned with the Add-Padding
 * header, and the core compares the suffixes on the device. The HIBP breach
 * catalog is downloaded whole and kept a week in the cache; ranges stay in
 * memory an hour and are dropped on lock. The 2FA and passkey checks read the
 * site pack shipped with the app (docs/site-pack.md): never a request per
 * site. As on iPhone, no newer pack is downloaded until the app carries the
 * pack's public key.
 *
 * HTTPS only, no cookie, no credential; nothing about the vault is sent but
 * the prefixes.
 */
class WatchtowerFetcher(private val context: Context) {
    private val prefs = context.getSharedPreferences("watchtower", Context.MODE_PRIVATE)
    private val dir = File(context.cacheDir, "watchtower")

    /** "Vérifier les fuites", on by default as on iPhone. */
    var checkBreaches: Boolean
        get() = prefs.getBoolean("checkBreaches", true)
        set(v) { prefs.edit().putBoolean("checkBreaches", v).apply() }

    private val ranges = mutableMapOf<String, Pair<ByteArray, Long>>()

    @Synchronized
    fun clear() = ranges.clear()

    class Directories(val sitePack: ByteArray?, val breaches: ByteArray?)

    /** The shipped site pack, read once; null when missing or not a pack the core accepts. */
    private val sitePack: ByteArray? by lazy {
        runCatching {
            val bytes = context.assets.open(SITE_PACK_ASSET).use { it.readBytes() }
            me.somalabs.onepass.core.sitePackVersion(bytes)
            bytes
        }.getOrNull()
    }

    /** The catalogs on disk (fresh or not when offline), downloaded first when [network]. */
    fun directories(network: Boolean): Directories {
        fun one(name: String, url: String): ByteArray? {
            val f = File(dir, name)
            val fresh = f.exists() && System.currentTimeMillis() - f.lastModified() < CATALOG_LIFETIME_MS
            if (network && !fresh) get(url, MAX_CATALOG)?.let { body ->
                dir.mkdirs()
                val tmp = File(dir, "$name.tmp")
                tmp.writeBytes(body)
                tmp.renameTo(f)
                return body
            }
            return if (f.exists()) runCatching { f.readBytes() }.getOrNull() else null
        }
        return Directories(sitePack, one("breaches.json", BREACHES_URL))
    }

    /** The ranges of [prefixes], from memory when fresh, else downloaded six at a time. A failed one is left out. */
    fun ranges(prefixes: List<String>, progress: (done: Int, total: Int) -> Unit = { _, _ -> }): List<FfiRangeResponse> {
        val now = System.currentTimeMillis()
        val wanted = prefixes.filter(::valid).distinct().sorted()
        val out = mutableListOf<FfiRangeResponse>()
        val missing = mutableListOf<String>()
        synchronized(this) {
            ranges.entries.removeAll { now - it.value.second > RANGE_LIFETIME_MS }
            wanted.forEach { p -> ranges[p]?.let { out += FfiRangeResponse(p, it.first) } ?: missing.add(p) }
        }
        if (missing.isEmpty()) return out
        val pool = Executors.newFixedThreadPool(6)
        try {
            val futures = missing.map { p -> pool.submit(Callable { p to get(RANGE_BASE + p, MAX_RANGE) }) }
            futures.forEachIndexed { i, f ->
                val (p, body) = runCatching { f.get(60, TimeUnit.SECONDS) }.getOrNull() ?: return@forEachIndexed
                if (body != null) {
                    synchronized(this) { ranges[p] = body to System.currentTimeMillis() }
                    out += FfiRangeResponse(p, body)
                }
                progress(i + 1, missing.size)
            }
        } finally {
            pool.shutdownNow()
        }
        return out
    }

    /** Exactly 5 upper-case hex characters: nothing else reaches a URL. */
    private fun valid(p: String) = p.length == 5 && p.all { it in '0'..'9' || it in 'A'..'F' }

    /** A GET over HTTPS, given up past [limit] bytes; null on any failure. */
    private fun get(url: String, limit: Int): ByteArray? = runCatching {
        val c = URL(url).openConnection() as HttpsURLConnection
        try {
            c.connectTimeout = 15_000
            c.readTimeout = 30_000
            c.useCaches = false
            c.instanceFollowRedirects = false
            c.setRequestProperty("User-Agent", "Cleon-Android")
            if (url.startsWith(RANGE_BASE)) c.setRequestProperty("Add-Padding", "true")
            if (c.responseCode != HttpURLConnection.HTTP_OK) return null
            c.inputStream.use { input ->
                val out = ByteArrayOutputStream()
                val buf = ByteArray(32 * 1024)
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    if (out.size() + n > limit) return null
                    out.write(buf, 0, n)
                }
                out.toByteArray()
            }
        } finally {
            c.disconnect()
        }
    }.getOrNull()

    companion object {
        const val RANGE_BASE = "https://api.pwnedpasswords.com/range/"
        const val SITE_PACK_ASSET = "onepass-sites.json"
        const val BREACHES_URL = "https://haveibeenpwned.com/api/v3/breaches"
        private const val MAX_RANGE = 4 shl 20
        private const val MAX_CATALOG = 16 shl 20
        private const val RANGE_LIFETIME_MS = 3_600_000L
        private const val CATALOG_LIFETIME_MS = 7 * 86_400_000L
    }
}
