package me.somalabs.onepass.ui

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.util.LruCache
import java.io.FileInputStream
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.text.Normalizer
import org.json.JSONObject

/**
 * The brand icons shipped with the app (iPhone: `IconPack`), keyed by domain:
 * the same pack as iOS (`apple/IconPack/onepass-icons.bin`, built by
 * scripts/icon_pack.py from open sets, licenses in docs/icon-pack.md), in the
 * assets uncompressed and memory mapped. Nothing is ever asked of a server.
 *
 * Format 1 (big-endian): "OPIP", a format byte, the index length (u32), the
 * index (JSON: `icons` as [offset, length, flags], `domains`, optional
 * `names` and `tenants`), then the icons (square lossless WebP).
 */
class IconPack private constructor(private val data: ByteBuffer, private val start: Int, index: JSONObject) {
    class Icon(val bitmap: Bitmap, val monochrome: Boolean)

    private val icons: List<IntArray>
    private val domains = HashMap<String, Int>()
    private val names = HashMap<String, Int>()
    private val tenants = HashSet<String>()
    private val cache = LruCache<Int, Icon>(96)

    init {
        val arr = index.getJSONArray("icons")
        icons = (0 until arr.length()).map { i -> arr.getJSONArray(i).let { intArrayOf(it.getInt(0), it.getInt(1), it.getInt(2)) } }
        val blob = data.capacity() - start
        icons.forEach { require(it[0] >= 0 && it[1] > 0 && it[0] <= blob - it[1]) { "icon out of bounds" } }
        index.getJSONObject("domains").let { o -> o.keys().forEach { k -> o.getInt(k).takeIf { it in icons.indices }?.let { domains[k] = it } } }
        index.optJSONObject("names")?.let { o -> o.keys().forEach { k -> o.getInt(k).takeIf { it in icons.indices }?.let { names[k] = it } } }
        index.optJSONArray("tenants")?.let { a -> (0 until a.length()).forEach { tenants += a.getString(it) } }
    }

    /** The icon of [host]: itself without www., then each parent down to two labels; a tenant gives its icon to itself only. */
    fun forHost(host: String): Icon? {
        var name = host.lowercase().trimEnd('.').removePrefix("www.")
        val labels = name.split('.').toMutableList()
        if (labels.size < 2 || labels.any { it.isEmpty() }) return null
        var first = true
        while (labels.size >= 2) {
            name = labels.joinToString(".")
            domains[name]?.let { n -> if (first || name !in tenants) return icon(n) }
            labels.removeAt(0)
            first = false
        }
        return null
    }

    /** A brand named by an item's title, for an item without a web address. */
    fun forTitle(title: String): Icon? {
        val t = title.trim().lowercase()
        if (!t.contains(' ') && t.contains('.')) forHost(t)?.let { return it }
        val key = Normalizer.normalize(t.replace("&", "and"), Normalizer.Form.NFD).filter { it in 'a'..'z' || it in '0'..'9' }
        if (key.length < 3) return null
        return names[key]?.let(::icon)
    }

    private fun icon(n: Int): Icon? {
        cache.get(n)?.let { return it }
        val (offset, length, flags) = icons[n].let { Triple(it[0], it[1], it[2]) }
        val bytes = ByteArray(length)
        synchronized(data) {
            data.position(start + offset)
            data.get(bytes)
        }
        val bmp = BitmapFactory.decodeByteArray(bytes, 0, length) ?: return null
        return Icon(bmp, flags and 1 != 0).also { cache.put(n, it) }
    }

    companion object {
        @Volatile
        var shared: IconPack? = null
            private set

        /** Maps the pack from the assets (once, off the main thread); a bad pack leaves the category art. */
        fun load(context: Context) {
            if (shared != null) return
            runCatching {
                context.assets.openFd("onepass-icons.bin").use { fd ->
                    FileInputStream(fd.fileDescriptor).channel.use { ch ->
                        val map = ch.map(FileChannel.MapMode.READ_ONLY, fd.startOffset, fd.length)
                        val head = ByteArray(9).also { map.get(it) }
                        require(String(head, 0, 4) == "OPIP" && head[4].toInt() == 1) { "not a pack" }
                        val len = ((head[5].toInt() and 0xff) shl 24) or ((head[6].toInt() and 0xff) shl 16) or ((head[7].toInt() and 0xff) shl 8) or (head[8].toInt() and 0xff)
                        require(len in 1..(8 shl 20)) { "index size" }
                        val json = ByteArray(len).also { map.get(it) }
                        shared = IconPack(map, 9 + len, JSONObject(String(json)))
                    }
                }
            }
        }

        /** The host of an item's web address ("https://x.y/z", "x.y"). */
        fun host(url: String?): String? {
            val u = url?.trim()?.takeIf { it.isNotEmpty() } ?: return null
            return runCatching { android.net.Uri.parse(if (u.contains("://")) u else "https://$u").host }.getOrNull()?.lowercase()
        }
    }
}
