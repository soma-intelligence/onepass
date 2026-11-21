package me.somalabs.onepass.screens

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.graphics.BitmapFactory
import android.graphics.pdf.PdfRenderer
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import java.io.File
import java.security.SecureRandom
import me.somalabs.onepass.AttachmentProvider
import me.somalabs.onepass.MainActivity
import me.somalabs.onepass.R
import me.somalabs.onepass.core.FfiAttachment
import me.somalabs.onepass.core.FfiItem
import me.somalabs.onepass.core.OnePassException

/**
 * An item's files (ItemAttachmentsSection on iPhone): the list with name and
 * size, "Ajouter un fichier…" (system file picker, 20 MB at most), and for
 * each file Aperçu, Exporter… and Supprimer….
 *
 * A file is only ever decrypted into the app's private cache: images, PDF and
 * text are previewed in the app (FLAG_SECURE outside debug builds); another
 * kind is handed to an app the user picks through [AttachmentProvider], with a
 * read grant on that one URI. Exporting writes where the user chooses (SAF).
 * The cache is emptied when OnePass locks.
 */
class Attachments(private val a: MainActivity) {
    private val ui get() = a.ui

    fun section(item: FfiItem, changed: () -> Unit): View {
        val col = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL }
        col.addView(ui.capsLabel(a.t("Pièces jointes", "Attachments")))
        val rows = item.attachments.map { att -> row(item, att, changed) } +
            ui.row(icon = ui.glyph(R.drawable.ic_paperclip, ui.accent, 22), title = a.t("Ajouter un fichier…", "Add a File…"), titleColor = ui.readableAccent, chevron = false) { add(item, changed) }
        col.addView(ui.inset(ui.card(*rows.toTypedArray())))
        return col
    }

    private fun row(item: FfiItem, att: FfiAttachment, changed: () -> Unit): View {
        val more = FrameLayout(a).apply {
            setPadding(ui.dp(10), ui.dp(10), ui.dp(10), ui.dp(10))
            contentDescription = a.t("Actions sur le fichier", "File actions")
            addView(ui.glyph(R.drawable.ic_more, ui.secondary, 22))
            isClickable = true
        }
        more.setOnClickListener {
            val del = a.t("Supprimer…", "Delete…")
            a.menu(more, listOf(
                Triple(R.drawable.ic_eye, a.t("Aperçu", "Preview")) { preview(item, att) },
                Triple(R.drawable.ic_share, a.t("Exporter…", "Export…")) { export(item, att) },
                Triple(R.drawable.ic_arrow_forward, a.t("Ouvrir dans…", "Open In…")) { load(item, att) { openWith(att, it, ask = false) } },
                Triple(R.drawable.ic_trash, del) { remove(item, att, changed) },
            ), setOf(del))
        }
        return ui.row(icon = ui.glyph(R.drawable.ic_paperclip, ui.secondary, 22), title = att.name, subtitle = size(att.size.toLong()), chevron = false, trailing = more) { preview(item, att) }
    }

    private fun size(bytes: Long): String = android.text.format.Formatter.formatShortFileSize(a, bytes)

    // ---- add -------------------------------------------------------------------------------------------

    private fun add(item: FfiItem, changed: () -> Unit) {
        val pick = Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*")
        a.launch(pick) { code, data ->
            val uri = data?.data
            if (code != Activity.RESULT_OK || uri == null) return@launch
            val s = a.session() ?: return@launch
            a.background({
                val cr = a.contentResolver
                var name = "file"
                var len = -1L
                cr.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { c ->
                    if (c.moveToFirst()) {
                        c.getString(0)?.let { name = it }
                        if (!c.isNull(1)) len = c.getLong(1)
                    }
                }
                if (len > MAX_BYTES) throw TooLarge()
                val bytes = cr.openInputStream(uri)?.use { input ->
                    val out = java.io.ByteArrayOutputStream()
                    val buf = ByteArray(64 * 1024)
                    var total = 0L
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        total += n
                        if (total > MAX_BYTES) throw TooLarge()
                        out.write(buf, 0, n)
                    }
                    out.toByteArray()
                } ?: throw java.io.IOException()
                val mime = cr.getType(uri) ?: "application/octet-stream"
                try {
                    s.addAttachment(item.vaultId, item.id, name, mime, bytes)
                } finally {
                    bytes.fill(0)
                }
                name
            }) { r ->
                r.onSuccess { name -> a.toast(a.t("Fichier ajouté : $name", "File added: $name")); changed() }
                    .onFailure {
                        a.toast(when (it) {
                            is TooLarge -> a.t("Ce fichier dépasse 20 Mo, la taille maximale d'une pièce jointe.", "This file is over 20 MB, the largest attachment allowed.")
                            is java.io.IOException, is SecurityException -> a.t("Impossible de lire ce fichier.", "Can't read this file.")
                            else -> a.message(it)
                        })
                    }
            }
        }
    }

    private class TooLarge : Exception()

    // ---- remove ----------------------------------------------------------------------------------------

    private fun remove(item: FfiItem, att: FfiAttachment, changed: () -> Unit) {
        a.confirm(a.t("Supprimer « ${att.name} » ? Le fichier est effacé de l'élément sur tous tes appareils.",
            "Delete “${att.name}”? The file is removed from the item on all your devices."), a.t("Supprimer le fichier", "Delete File")) {
            val s = a.session() ?: return@confirm
            a.background({ s.removeAttachment(item.vaultId, item.id, att.id) }) { r ->
                r.onSuccess { changed() }.onFailure { a.toast(a.message(it)) }
            }
        }
    }

    // ---- read ------------------------------------------------------------------------------------------

    private fun load(item: FfiItem, att: FfiAttachment, then: (ByteArray) -> Unit) {
        val s = a.session() ?: return
        a.background({ s.attachmentData(item.vaultId, item.id, att.id) }) { r ->
            r.onSuccess(then).onFailure {
                a.toast(if (it is OnePassException.NotFound) a.t("Ce fichier n'est pas encore arrivé sur cet appareil. Réessaie après la synchronisation.", "This file hasn't reached this device yet. Try again after syncing.") else a.message(it))
            }
        }
    }

    private fun export(item: FfiItem, att: FfiAttachment) {
        val create = Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE)
            .setType(att.mime.ifBlank { "application/octet-stream" }).putExtra(Intent.EXTRA_TITLE, att.name)
        a.launch(create) { code, data ->
            val uri = data?.data
            if (code != Activity.RESULT_OK || uri == null) return@launch
            load(item, att) { bytes ->
                a.background({
                    try {
                        a.contentResolver.openOutputStream(uri, "wt")?.use { it.write(bytes) } ?: throw java.io.IOException()
                    } finally {
                        bytes.fill(0)
                    }
                }) { r -> r.onSuccess { a.toast(a.t("Exporté", "Exported")) }.onFailure { a.toast(a.message(it)) } }
            }
        }
    }

    private fun preview(item: FfiItem, att: FfiAttachment) {
        load(item, att) { bytes ->
            val mime = att.mime.lowercase()
            val name = att.name.lowercase()
            when {
                mime.startsWith("image/") -> BitmapFactory.decodeByteArray(bytes, 0, bytes.size)?.let { bmp ->
                    bytes.fill(0)
                    show(att) { ImageView(a).apply { setImageBitmap(bmp); adjustViewBounds = true; scaleType = ImageView.ScaleType.FIT_CENTER } }
                } ?: openWith(att, bytes)
                mime == "application/pdf" || name.endsWith(".pdf") -> pdf(att, bytes)
                mime.startsWith("text/") || mime == "application/json" || name.endsWith(".txt") || name.endsWith(".md") -> {
                    val txt = String(bytes, Charsets.UTF_8)
                    bytes.fill(0)
                    show(att) { ui.text(txt, 15f, ui.label).apply { setTextIsSelectable(true); typeface = android.graphics.Typeface.MONOSPACE; setPadding(ui.dp(16), ui.dp(12), ui.dp(16), ui.dp(12)) } }
                }
                else -> openWith(att, bytes)
            }
        }
    }

    /** A PDF drawn page by page in the app, from a private cache file. */
    private fun pdf(att: FfiAttachment, bytes: ByteArray) {
        val file = cacheFile(a, att.name)
        file.writeBytes(bytes)
        bytes.fill(0)
        val pages = runCatching {
            ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY).use { fd ->
                PdfRenderer(fd).use { r ->
                    val width = a.resources.displayMetrics.widthPixels
                    (0 until minOf(r.pageCount, 50)).map { i ->
                        r.openPage(i).use { p ->
                            val h = (width.toFloat() * p.height / p.width).toInt()
                            val bmp = android.graphics.Bitmap.createBitmap(width, h, android.graphics.Bitmap.Config.ARGB_8888)
                            bmp.eraseColor(android.graphics.Color.WHITE)
                            p.render(bmp, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)
                            bmp
                        }
                    }
                }
            }
        }.getOrNull()
        file.delete()
        if (pages == null) return a.toast(a.t("Impossible de lire ce fichier.", "Can't read this file."))
        show(att) {
            LinearLayout(a).apply {
                orientation = LinearLayout.VERTICAL
                pages.forEachIndexed { i, bmp ->
                    addView(ImageView(a).apply { setImageBitmap(bmp); adjustViewBounds = true; contentDescription = a.t("Page ${i + 1} sur ${pages.size}", "Page ${i + 1} of ${pages.size}") },
                        LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { bottomMargin = ui.dp(8) })
                }
            }
        }
    }

    /** No preview here: written to the private cache and offered to another app, read only. */
    private fun openWith(att: FfiAttachment, bytes: ByteArray, ask: Boolean = true) {
        val file = cacheFile(a, att.name)
        file.writeBytes(bytes)
        bytes.fill(0)
        val uri: Uri = AttachmentProvider.uriFor(a, file, att.mime)
        val view = Intent(Intent.ACTION_VIEW).setDataAndType(uri, att.mime.ifBlank { "application/octet-stream" })
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        val go = {
            try {
                a.startActivity(Intent.createChooser(view, att.name).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION))
            } catch (_: android.content.ActivityNotFoundException) {
                a.toast(a.t("Pas d'aperçu pour ce type de fichier. Exporte-le pour l'ouvrir dans une autre app.", "No preview for this kind of file. Export it to open it in another app."))
            }
        }
        if (ask) a.confirm(a.t("Pas d'aperçu pour ce type de fichier. L'ouvrir dans une autre app ?", "No preview for this kind of file. Open it in another app?"), a.t("Ouvrir", "Open"), destructive = false) { go() } else go()
    }

    private fun show(att: FfiAttachment, content: () -> View) {
        a.sheet(att.name, a.t("Fermer", "Close"), null) { _ ->
            LinearLayout(a).apply {
                orientation = LinearLayout.VERTICAL
                gravity = Gravity.CENTER_HORIZONTAL
                setPadding(ui.dp(8), ui.dp(8), ui.dp(8), ui.dp(40))
                addView(content(), LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
            }
        }
    }

    companion object {
        const val MAX_BYTES = 20L * 1024 * 1024

        private fun dir(c: Context) = File(c.cacheDir, "attachments")

        /** A fresh file in a random folder of the private cache. */
        fun cacheFile(c: Context, name: String): File {
            val r = ByteArray(12).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }
            val folder = File(dir(c), r).apply { mkdirs() }
            val safe = name.replace(Regex("[/\\\\:*?\"<>|\\u0000]"), "_").take(120).ifBlank { "file" }
            return File(folder, safe)
        }

        /** Empties the cache of decrypted files (on lock and at launch). */
        fun clearCache(c: Context) {
            dir(c).listFiles()?.forEach { f -> f.walkBottomUp().forEach { runCatching { if (it.isFile) it.writeBytes(ByteArray(0)); it.delete() } } }
        }
    }
}
