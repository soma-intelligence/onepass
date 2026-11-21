package me.somalabs.onepass

import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import java.io.File
import java.io.FileNotFoundException

/**
 * Hands one decrypted attachment, already written to the app's private cache,
 * to the app the user picked to open it: read only, never exported, reachable
 * only through the per-URI grant of the Intent (FileProvider without AndroidX).
 *
 * URI: content://<package>.attachments/<folder>/<name>?mime=<type>; the file
 * must be inside cache/attachments.
 */
class AttachmentProvider : ContentProvider() {
    override fun onCreate() = true

    private fun file(uri: Uri): File {
        val ctx = context ?: throw FileNotFoundException()
        val base = File(ctx.cacheDir, "attachments").canonicalFile
        val segs = uri.pathSegments
        if (segs.size != 2) throw FileNotFoundException()
        val f = File(File(base, segs[0]), segs[1]).canonicalFile
        if (f.parentFile?.parentFile != base || !f.isFile) throw FileNotFoundException()
        return f
    }

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        if (mode != "r") throw SecurityException("read only")
        return ParcelFileDescriptor.open(file(uri), ParcelFileDescriptor.MODE_READ_ONLY)
    }

    override fun query(uri: Uri, projection: Array<out String>?, selection: String?, selectionArgs: Array<out String>?, sortOrder: String?): Cursor {
        val f = file(uri)
        val cols = projection ?: arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE)
        val row = cols.map { c ->
            when (c) {
                OpenableColumns.DISPLAY_NAME -> f.name
                OpenableColumns.SIZE -> f.length()
                else -> null
            }
        }
        return MatrixCursor(cols, 1).apply { addRow(row) }
    }

    override fun getType(uri: Uri): String = uri.getQueryParameter("mime")?.takeIf { it.contains('/') } ?: "application/octet-stream"
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?) = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?) = 0

    companion object {
        fun uriFor(c: Context, f: File, mime: String): Uri = Uri.Builder().scheme("content").authority(c.packageName + ".attachments")
            .appendPath(f.parentFile!!.name).appendPath(f.name).appendQueryParameter("mime", mime).build()
    }
}
