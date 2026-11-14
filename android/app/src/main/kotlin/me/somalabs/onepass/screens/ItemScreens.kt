package me.somalabs.onepass.screens

import android.app.Dialog
import android.content.Intent
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.net.Uri
import android.text.Editable
import android.text.InputType
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.TextWatcher
import android.text.style.ForegroundColorSpan
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.GridLayout
import android.widget.LinearLayout
import android.widget.SeekBar
import android.widget.TextView
import java.text.DateFormat
import java.util.Date
import me.somalabs.onepass.MainActivity
import me.somalabs.onepass.R
import me.somalabs.onepass.core.FfiFieldType
import me.somalabs.onepass.core.FfiFieldValue
import me.somalabs.onepass.core.FfiItem
import me.somalabs.onepass.core.FfiItemType
import me.somalabs.onepass.core.FfiMatchRule
import me.somalabs.onepass.core.FfiPasswordRecipe
import me.somalabs.onepass.core.FfiUrl
import me.somalabs.onepass.core.generatePassword
import me.somalabs.onepass.core.passwordEntropyBits
import me.somalabs.onepass.core.passwordStrengthBits
import me.somalabs.onepass.core.totpNow
import me.somalabs.onepass.ui.Category
import me.somalabs.onepass.ui.Ios

/**
 * The item as on iPhone: the detail (ItemDetailView: header, section cards
 * with an accent label over each value and a "⋯" menu, strength, live code,
 * websites, notes, tags, "Modifié le", actions), the editor, the type picker
 * ("Que veux-tu ajouter ?"), the generator, the password history and the
 * large type view.
 *
 * Secrets are drawn masked; their value is read again from the core only when
 * the user reveals, copies or enlarges it.
 */
class ItemScreens(private val a: MainActivity) {
    private val ui get() = a.ui

    // ---- values ------------------------------------------------------------------------------------

    private fun isSecret(k: FfiFieldType) = k == FfiFieldType.PASSWORD || k == FfiFieldType.CONCEALED ||
        k == FfiFieldType.OTP || k == FfiFieldType.MNEMONIC || k == FfiFieldType.SSH_KEY

    fun display(v: FfiFieldValue): String? = when (v) {
        is FfiFieldValue.Text -> v.value
        is FfiFieldValue.Concealed -> v.value
        is FfiFieldValue.Password -> v.value
        is FfiFieldValue.Url -> v.value
        is FfiFieldValue.Email -> v.value
        is FfiFieldValue.Phone -> v.value
        is FfiFieldValue.Menu -> v.value
        is FfiFieldValue.Otp -> v.value
        is FfiFieldValue.Mnemonic -> v.value
        is FfiFieldValue.Number -> v.value.toString()
        is FfiFieldValue.Date -> DateFormat.getDateInstance(DateFormat.LONG).format(
            java.util.GregorianCalendar(v.value.year.toInt(), v.value.month.toInt() - 1, v.value.day.toInt()).time)
        is FfiFieldValue.MonthYear -> "%02d/%04d".format(v.month.toInt(), v.year.toInt())
        is FfiFieldValue.Money -> "%d,%02d %s".format(v.minorUnits / 100, kotlin.math.abs(v.minorUnits % 100), v.currency)
        is FfiFieldValue.Address -> listOf(v.value.line1, v.value.line2, listOf(v.value.postalCode, v.value.city).filter { it.isNotBlank() }.joinToString(" "), v.value.region, v.value.country).filter { it.isNotBlank() }.joinToString("\n")
        is FfiFieldValue.SshKey -> v.value.privatePem
        is FfiFieldValue.Barcode -> v.value
        is FfiFieldValue.Location -> v.value.address ?: v.value.label
        is FfiFieldValue.Passkey -> "${v.value.userName} (${v.value.rpId})"
        is FfiFieldValue.File -> v.value.name
        else -> null
    }?.takeIf { it.isNotEmpty() }

    /** Reads one field's value again from the core (never kept on screen). */
    private fun fresh(item: FfiItem, fieldId: String): String? = runCatching {
        a.vault.session?.item(item.vaultId, item.id)?.sections?.flatMap { it.fields }?.firstOrNull { it.id == fieldId }?.let { display(it.value) }
    }.getOrNull()

    private fun strengthLabel(bits: Double): Pair<String, Int> {
        val level = listOf(40.0, 60.0, 80.0, 100.0).count { bits >= it }
        val label = listOf(a.t("Trop court", "Too short"), a.t("Faible", "Weak"), a.t("Moyen", "Fair"), a.t("Bon", "Good"), a.t("Excellent", "Excellent"))[level]
        val color = when (level) { 0, 1 -> ui.red; 2 -> ui.orange; else -> ui.green }
        return label to color
    }

    /** Digits in blue, symbols in red, as the iPhone draws passwords. */
    fun colored(p: String): CharSequence {
        val b = SpannableStringBuilder(p)
        p.forEachIndexed { i, ch ->
            val c = when { ch.isDigit() -> ui.blue; !ch.isLetter() -> ui.red; else -> null }
            c?.let { b.setSpan(ForegroundColorSpan(it), i, i + 1, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE) }
        }
        return b
    }

    // ---- detail ------------------------------------------------------------------------------------------

    fun detail(vaultId: String, itemId: String) {
        val s = a.session() ?: return
        a.background({ s.item(vaultId, itemId) }) { r ->
            r.onSuccess { item ->
                a.summaries.firstOrNull { it.id == item.id }?.let(a::opened)
                a.push { detailPage(item) }
            }.onFailure { a.toast(a.message(it)) }
        }
    }

    private fun reopen(item: FfiItem) {
        val s = a.session() ?: return
        a.background({ s.item(item.vaultId, item.id) }) { r ->
            r.onSuccess { fresh -> a.changed { a.pop(); a.push { detailPage(fresh) } } }.onFailure { a.changed { a.pop() } }
        }
    }

    private fun detailPage(item: FfiItem): View {
        val s = a.vault.session!!
        val cat = Category.of(item.itemType)
        val trashed = item.trashedAt != null
        val star = a.barIcon(if (item.favorite) R.drawable.ic_star_fill else R.drawable.ic_star, a.t("Favori", "Favorite")) {
            a.background({ s.setFavorite(item.vaultId, item.id, !item.favorite) }) { reopen(item) }
        }.apply { if (item.favorite) ((this as FrameLayout).getChildAt(0) as android.widget.ImageView).imageTintList = ColorStateList.valueOf(ui.amberStar) }
        val edit = a.barText(a.t("Modifier", "Edit")) { edit(item, isNew = false) }
        val more = a.barIcon(R.drawable.ic_more_circle, a.t("Actions", "Actions")) { v -> actions(v, item) }
        val trailing = if (trashed) listOf(more) else listOf(star, edit, more)
        return a.pushedPage(null, trailing) {
            // Header: icon, title, "Catégorie · sous-titre", vault chip.
            val head = LinearLayout(a).apply { gravity = Gravity.CENTER_VERTICAL; setPadding(ui.dp(16), ui.dp(12), ui.dp(16), ui.dp(4)) }
            head.addView(a.itemIcon(item.itemType, 56).apply { (layoutParams as LinearLayout.LayoutParams).marginEnd = ui.dp(14) })
            val names = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL }
            names.addView(ui.text(item.title.ifBlank { a.t("Sans titre", "Untitled") }, 26f, ui.label, 700))
            val sub = a.summaries.firstOrNull { it.id == item.id }?.subtitle.orEmpty()
            names.addView(ui.text(listOf(cat.singular(a), sub).filter { it.isNotBlank() }.joinToString(" · "), 15f, ui.secondary).apply { setPadding(0, ui.dp(3), 0, 0); maxLines = 1 })
            head.addView(names, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            addView(head)
            val chips = LinearLayout(a).apply { setPadding(ui.dp(16), ui.dp(8), ui.dp(16), 0) }
            a.vaults.firstOrNull { it.id == item.vaultId }?.let { v ->
                chips.addView(ui.chip(v.meta.name, Ios.vaultColor(v.meta.color)))
            }
            if (item.archived) chips.addView(ui.chip(a.t("Archivé", "Archived"), ui.secondary).apply { (layoutParams as? LinearLayout.LayoutParams)?.marginStart = ui.dp(8) }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { marginStart = ui.dp(8) })
            if (trashed) chips.addView(ui.chip(a.t("Dans la corbeille", "In Trash"), ui.red), LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { marginStart = ui.dp(8) })
            addView(chips)

            for (section in item.sections) {
                val fields = section.fields.filter { it.value !is FfiFieldValue.Empty && display(it.value) != null }
                if (fields.isEmpty()) continue
                addView(ui.capsLabel(section.label.ifBlank { cat.singular(a) }))
                addView(ui.inset(ui.card(*fields.map { f -> fieldRow(item, f.id, f.label, f.kind, if (isSecret(f.kind)) null else display(f.value)) }.toTypedArray())))
            }
            if (item.urls.isNotEmpty()) {
                addView(ui.capsLabel(a.t("Sites web", "Websites")))
                addView(ui.inset(ui.card(*item.urls.map { u ->
                    valueRow(u.label.ifBlank { a.t("site web", "website") }, u.url, trailing = ui.glyph(R.drawable.ic_link, ui.accent, 22).apply {
                        isClickable = true
                        setOnClickListener {
                            val url = if (u.url.contains("://")) u.url else "https://${u.url}"
                            runCatching { a.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }
                        }
                    }) { a.copy(u.url, false) }
                }.toTypedArray())))
            }
            if (item.notes.isNotBlank()) {
                addView(ui.capsLabel(a.t("Notes", "Notes")))
                addView(ui.inset(ui.card(ui.text(item.notes, 17f, ui.label).apply {
                    setPadding(ui.dp(16), ui.dp(12), ui.dp(16), ui.dp(12))
                    setTextIsSelectable(true)
                })))
            }
            if (item.tags.isNotEmpty()) {
                addView(ui.capsLabel("Tags"))
                val row = LinearLayout(a).apply { setPadding(ui.dp(16), 0, ui.dp(16), 0) }
                item.tags.forEach { tag -> row.addView(ui.chip(tag), LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { marginEnd = ui.dp(8) }) }
                addView(android.widget.HorizontalScrollView(a).apply { isHorizontalScrollBarEnabled = false; addView(row) })
            }
            val df = DateFormat.getDateTimeInstance(DateFormat.LONG, DateFormat.SHORT)
            val footer = LinearLayout(a).apply {
                orientation = LinearLayout.VERTICAL
                gravity = Gravity.CENTER_HORIZONTAL
                setPadding(ui.dp(16), ui.dp(28), ui.dp(16), ui.dp(8))
            }
            footer.addView(ui.text(a.t("Modifié le ", "Modified ") + df.format(Date(item.updatedAt * 1000)), 13f, ui.secondary).apply { gravity = Gravity.CENTER })
            footer.addView(ui.text(a.t("Créé le ", "Created ") + df.format(Date(item.createdAt * 1000)), 13f, ui.tertiary).apply { gravity = Gravity.CENTER; setPadding(0, ui.dp(2), 0, 0) })
            if (item.passwordHistoryCount > 0u) {
                footer.addView(a.link(a.t("Historique des mots de passe", "Password History")) { a.push { history(item) } }.apply { gravity = Gravity.CENTER })
            }
            addView(footer)
        }
    }

    /** One field: the label in the accent above the value, "⋯" with Copier / Révéler / Afficher en grand. */
    private fun fieldRow(item: FfiItem, fieldId: String, label: String, kind: FfiFieldType, plain: String?): View {
        val secret = isSecret(kind)
        if (kind == FfiFieldType.OTP) return otpRow(item, fieldId, label)
        val value = ui.text(if (secret) "••••••••••" else plain.orEmpty(), 17f, ui.label).apply {
            if (kind == FfiFieldType.SSH_KEY || kind == FfiFieldType.MNEMONIC) maxLines = 3
        }
        var shown = false
        val col = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL }
        col.addView(ui.text(label, 13f, ui.readableAccent, 500))
        col.addView(value.apply { setPadding(0, ui.dp(3), 0, 0) })
        if (kind == FfiFieldType.PASSWORD) {
            fresh(item, fieldId)?.let { p ->
                val (txt, color) = strengthLabel(passwordStrengthBits(p))
                col.addView(strengthMeter(txt, color, passwordStrengthBits(p)))
            }
        }
        val row = LinearLayout(a).apply {
            gravity = Gravity.CENTER_VERTICAL
            minimumHeight = ui.dp(60)
            setPadding(ui.dp(16), ui.dp(10), ui.dp(6), ui.dp(10))
            background = ui.pressable(null)
            isClickable = true
            setOnClickListener { (if (secret) fresh(item, fieldId) else plain)?.let { a.copy(it, secret) } }
        }
        row.addView(col, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        val more = FrameLayout(a).apply {
            setPadding(ui.dp(10), ui.dp(10), ui.dp(10), ui.dp(10))
            contentDescription = a.t("Actions", "Actions")
            addView(ui.glyph(R.drawable.ic_more, ui.secondary, 22))
            isClickable = true
        }
        more.setOnClickListener {
            val entries = mutableListOf<Triple<Int, String, () -> Unit>>(
                Triple(R.drawable.ic_copy, a.t("Copier", "Copy")) { (if (secret) fresh(item, fieldId) else plain)?.let { a.copy(it, secret) } },
            )
            if (secret) entries += Triple(if (shown) R.drawable.ic_eye_off else R.drawable.ic_eye, if (shown) a.t("Masquer", "Conceal") else a.t("Révéler", "Reveal")) {
                shown = !shown
                value.text = if (shown) fresh(item, fieldId)?.let { if (kind == FfiFieldType.PASSWORD) colored(it) else it } ?: "" else "••••••••••"
                value.typeface = if (shown && kind == FfiFieldType.PASSWORD) Typeface.MONOSPACE else Typeface.DEFAULT
            }
            entries += Triple(R.drawable.ic_large_type, a.t("Afficher en grand", "Show in Large Type")) {
                (if (secret) fresh(item, fieldId) else plain)?.let { largeType(it) }
            }
            a.menu(more, entries)
        }
        row.addView(more)
        return row
    }

    private fun strengthMeter(label: String, color: Int, bits: Double): View = LinearLayout(a).apply {
        gravity = Gravity.CENTER_VERTICAL
        setPadding(0, ui.dp(8), 0, 0)
        val level = listOf(40.0, 60.0, 80.0, 100.0).count { bits >= it }
        val segs = LinearLayout(a)
        for (i in 0 until 4) segs.addView(View(a).apply { background = ui.rounded(if (i < level) color else ui.fill, 2) }, LinearLayout.LayoutParams(ui.dp(22), ui.dp(4)).apply { marginEnd = ui.dp(4) })
        addView(segs)
        addView(ui.text(label, 12f, ui.secondary).apply { setPadding(ui.dp(4), 0, 0, 0) })
    }

    private fun valueRow(label: String, value: String, trailing: View? = null, onClick: () -> Unit): View {
        val row = LinearLayout(a).apply {
            gravity = Gravity.CENTER_VERTICAL
            minimumHeight = ui.dp(60)
            setPadding(ui.dp(16), ui.dp(10), ui.dp(16), ui.dp(10))
            background = ui.pressable(null)
            isClickable = true
            setOnClickListener { onClick() }
        }
        val col = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL }
        col.addView(ui.text(label, 13f, ui.readableAccent, 500))
        col.addView(ui.text(value, 17f, ui.label).apply { setPadding(0, ui.dp(3), 0, 0); maxLines = 2 })
        row.addView(col, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        trailing?.let { row.addView(it) }
        return row
    }

    /** The live code "538 • 262" and the seconds left in a ring pill. */
    private fun otpRow(item: FfiItem, fieldId: String, label: String): View {
        val code = ui.text("––– • –––", 26f, ui.label, 600).apply { fontFeatureSettings = "tnum"; setPadding(0, ui.dp(3), 0, 0) }
        val left = ui.text("", 15f, ui.readableAccent, 600).apply {
            fontFeatureSettings = "tnum"
            background = ui.rounded(ui.fill, 14)
            setPadding(ui.dp(10), ui.dp(4), ui.dp(10), ui.dp(4))
        }
        var current: String? = null
        val secret = fresh(item, fieldId)
        a.tick(object : Runnable {
            override fun run() {
                val r = secret?.let { runCatching { totpNow(it, (System.currentTimeMillis() / 1000).toULong()) }.getOrNull() }
                if (r == null) {
                    code.text = a.t("Code indisponible", "Code unavailable"); code.textSize = 17f; left.visibility = View.GONE
                } else {
                    current = r.code
                    val half = r.code.length / 2
                    code.text = r.code.take(half) + " • " + r.code.drop(half)
                    left.text = "${r.remaining}"
                    left.setTextColor(if (r.remaining <= 5u) ui.red else ui.readableAccent)
                }
                a.main.postDelayed(this, 1000)
            }
        })
        val row = LinearLayout(a).apply {
            gravity = Gravity.CENTER_VERTICAL
            minimumHeight = ui.dp(64)
            setPadding(ui.dp(16), ui.dp(10), ui.dp(16), ui.dp(10))
            background = ui.pressable(null)
            isClickable = true
            setOnClickListener { current?.let { a.copy(it, true) } }
        }
        val col = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL }
        col.addView(ui.text(label.ifBlank { a.t("code à usage unique", "one-time password") }, 13f, ui.readableAccent, 500))
        col.addView(code)
        row.addView(col, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        row.addView(left)
        return row
    }

    private fun largeType(value: String) {
        val d = Dialog(a, android.R.style.Theme_DeviceDefault_NoActionBar_Fullscreen)
        val grid = GridLayout(a).apply { columnCount = 6; setPadding(ui.dp(16), ui.dp(16), ui.dp(16), ui.dp(16)) }
        value.forEachIndexed { i, ch ->
            val cell = LinearLayout(a).apply {
                orientation = LinearLayout.VERTICAL
                gravity = Gravity.CENTER
                background = ui.rounded(if (i % 2 == 0) ui.card else ui.raised, 8)
                setPadding(0, ui.dp(6), 0, ui.dp(4))
            }
            val color = when { ch.isDigit() -> ui.blue; !ch.isLetter() -> ui.red; else -> ui.label }
            cell.addView(ui.text(ch.toString(), 34f, color, 500).apply { typeface = Typeface.MONOSPACE; gravity = Gravity.CENTER })
            cell.addView(ui.text("${i + 1}", 11f, ui.secondary).apply { gravity = Gravity.CENTER })
            grid.addView(cell, GridLayout.LayoutParams(GridLayout.spec(GridLayout.UNDEFINED), GridLayout.spec(GridLayout.UNDEFINED, 1f)).apply { width = 0; setMargins(ui.dp(3), ui.dp(3), ui.dp(3), ui.dp(3)) })
        }
        val col = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL; setBackgroundColor(ui.page); gravity = Gravity.CENTER }
        col.addView(grid)
        col.addView(ui.capsule(a.t("Fermer", "Close"), prominent = false) { d.dismiss() }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { gravity = Gravity.CENTER_HORIZONTAL; topMargin = ui.dp(16) })
        d.setContentView(col)
        if (!a.debuggable) d.window?.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        d.show()
    }

    private fun history(item: FfiItem): View {
        val s = a.vault.session!!
        val entries = runCatching { s.passwordHistory(item.vaultId, item.id) }.getOrDefault(emptyList())
        val df = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT)
        return a.pushedPage(a.t("Historique des mots de passe", "Password History"), largeTitle = true) {
            addView(ui.footnote(a.t("Les mots de passe que cet élément a remplacés, du plus récent au plus ancien.", "The passwords this item replaced, newest first.")))
            addView(ui.inset(ui.card(*entries.sortedByDescending { it.replacedAt }.map { e ->
                var shown = false
                val v = ui.text("••••••••••", 17f, ui.label)
                val row = LinearLayout(a).apply { gravity = Gravity.CENTER_VERTICAL; setPadding(ui.dp(16), ui.dp(10), ui.dp(8), ui.dp(10)) }
                val col = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL }
                col.addView(ui.text(a.t("Remplacé le ", "Replaced ") + df.format(Date(e.replacedAt * 1000)), 13f, ui.readableAccent, 500))
                col.addView(v)
                row.addView(col, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
                row.addView(a.barIcon(R.drawable.ic_eye, a.t("Révéler", "Reveal")) { shown = !shown; v.text = if (shown) colored(e.value) else "••••••••••"; v.typeface = if (shown) Typeface.MONOSPACE else Typeface.DEFAULT })
                row.addView(a.barIcon(R.drawable.ic_copy, a.t("Copier", "Copy")) { a.copy(e.value, true) })
                row
            }.toTypedArray())))
        }
    }

    // ---- actions --------------------------------------------------------------------------------------------

    private fun actions(anchor: View, item: FfiItem) {
        val s = a.vault.session ?: return
        fun run(work: () -> Unit, after: () -> Unit) = a.background(work) { r -> r.onFailure { a.toast(a.message(it)) }; after() }
        val entries = mutableListOf<Triple<Int, String, () -> Unit>>()
        val del = a.t("Supprimer", "Delete")
        val delForever = a.t("Supprimer définitivement", "Delete Permanently")
        if (item.trashedAt != null) {
            entries += Triple(R.drawable.ic_restore, a.t("Restaurer", "Restore")) { run({ s.restoreItem(item.vaultId, item.id) }) { reopen(item) } }
            entries += Triple(R.drawable.ic_trash, delForever) {
                a.confirm(a.t("Supprimer définitivement « ${item.title} » ? Cette action est irréversible.", "Permanently delete “${item.title}”? This cannot be undone."), delForever) {
                    run({ s.deleteItem(item.vaultId, item.id) }) { a.changed { a.pop() } }
                }
            }
            a.menu(anchor, entries, setOf(delForever))
            return
        }
        entries += Triple(if (item.favorite) R.drawable.ic_star_fill else R.drawable.ic_star, if (item.favorite) a.t("Retirer des favoris", "Unfavorite") else a.t("Ajouter aux favoris", "Favorite")) {
            run({ s.setFavorite(item.vaultId, item.id, !item.favorite) }) { reopen(item) }
        }
        username(item)?.let { u -> entries += Triple(R.drawable.ic_copy, a.t("Copier l'identifiant", "Copy Username")) { a.copy(u, false) } }
        if (a.vaults.size > 1) entries += Triple(R.drawable.ic_folder, a.t("Déplacer…", "Move…")) {
            val others = a.vaults.filter { it.id != item.vaultId }
            android.app.AlertDialog.Builder(a).setTitle(a.t("Déplacer vers", "Move to"))
                .setItems(others.map { it.meta.name }.toTypedArray()) { _, i ->
                    run({ s.moveItem(item.id, item.vaultId, others[i].id) }) { a.changed { a.pop() } }
                }.show()
        }
        entries += Triple(R.drawable.ic_duplicate, a.t("Dupliquer", "Duplicate")) {
            run({
                val n = s.newItem(item.vaultId, item.itemType, item.title + a.t(" (copie)", " (copy)"))
                s.saveItem(item.copy(id = n.id, title = n.title, favorite = false, archived = false, trashedAt = null, createdAt = n.createdAt, updatedAt = n.updatedAt,
                    passwordHistoryCount = 0u, attachmentCount = 0u, attachments = emptyList()))
            }) { a.changed() }
        }
        entries += Triple(R.drawable.ic_archive, if (item.archived) a.t("Désarchiver", "Unarchive") else a.t("Archiver", "Archive")) {
            run({ if (item.archived) s.unarchiveItem(item.vaultId, item.id) else s.archiveItem(item.vaultId, item.id) }) { reopen(item) }
        }
        entries += Triple(R.drawable.ic_trash, del) {
            a.confirm(a.t("Mettre « ${item.title} » dans Supprimés récemment ?", "Move “${item.title}” to Recently Deleted?"), del) {
                run({ s.trashItem(item.vaultId, item.id) }) { a.changed { a.pop() } }
            }
        }
        a.menu(anchor, entries, setOf(del))
    }

    private fun username(item: FfiItem): String? {
        val fields = item.sections.flatMap { it.fields }
        val f = fields.firstOrNull { it.id == "username" } ?: fields.firstOrNull { it.kind == FfiFieldType.EMAIL }
        return f?.let { display(it.value) }
    }

    // ---- new item --------------------------------------------------------------------------------------------

    /** "Que veux-tu ajouter ?": every category as a tile, the vault on top when there are several. */
    fun newItem(preset: FfiItemType?) {
        val s = a.session() ?: return
        if (a.vaults.isEmpty()) return
        var vault = a.vaults.first()
        fun create(type: FfiItemType, d: Dialog) {
            d.dismiss()
            a.background({ s.newItem(vault.id, type, "") }) { r ->
                r.onSuccess { edit(it, isNew = true) }.onFailure { a.toast(a.message(it)) }
            }
        }
        if (preset != null) {
            a.background({ s.newItem(vault.id, preset, "") }) { r -> r.onSuccess { edit(it, isNew = true) } }
            return
        }
        a.sheet(a.t("Nouvel élément", "New Item"), a.t("Annuler", "Cancel"), null) { d ->
            val col = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL; setPadding(0, 0, 0, ui.dp(40)) }
            col.addView(ui.text(a.t("Que veux-tu ajouter ?", "What do you want to add?"), 28f, ui.label, 700).apply { setPadding(ui.dp(20), ui.dp(8), ui.dp(20), ui.dp(12)) })
            if (a.vaults.size > 1) {
                val chips = LinearLayout(a).apply { setPadding(ui.dp(16), 0, ui.dp(16), ui.dp(12)) }
                fun drawChips() {
                    chips.removeAllViews()
                    a.vaults.forEach { v ->
                        val on = v.id == vault.id
                        chips.addView(ui.chip(v.meta.name, if (on) Ios.vaultColor(v.meta.color) else ui.secondary).apply {
                            if (on) setTextColor(Color.WHITE)
                            if (on) background = ui.rounded(Ios.vaultColor(v.meta.color), 9)
                            isClickable = true
                            setOnClickListener { vault = v; drawChips() }
                        }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { marginEnd = ui.dp(8) })
                    }
                }
                drawChips()
                col.addView(android.widget.HorizontalScrollView(a).apply { isHorizontalScrollBarEnabled = false; addView(chips) })
            }
            val grid = GridLayout(a).apply { columnCount = 3; setPadding(ui.dp(12), 0, ui.dp(12), 0) }
            Category.ALL.forEach { c ->
                val cell = LinearLayout(a).apply {
                    orientation = LinearLayout.VERTICAL
                    gravity = Gravity.CENTER_HORIZONTAL
                    background = ui.pressable(ui.rounded(ui.card, 16, ui.hairline), 16)
                    setPadding(ui.dp(6), ui.dp(14), ui.dp(6), ui.dp(12))
                    isClickable = true
                    contentDescription = c.singular(a)
                    setOnClickListener { create(c.type, d) }
                }
                cell.addView(a.itemIcon(c.type, 48))
                cell.addView(ui.text(c.singular(a), 13f, ui.label, 500).apply { gravity = Gravity.CENTER; maxLines = 2; setPadding(0, ui.dp(8), 0, 0) })
                grid.addView(cell, GridLayout.LayoutParams(GridLayout.spec(GridLayout.UNDEFINED), GridLayout.spec(GridLayout.UNDEFINED, 1f)).apply {
                    width = 0; height = ui.dp(118); setMargins(ui.dp(4), ui.dp(4), ui.dp(4), ui.dp(4))
                })
            }
            col.addView(grid)
            col
        }
    }

    // ---- editor ----------------------------------------------------------------------------------------------

    private val textKinds = setOf(
        FfiFieldType.TEXT, FfiFieldType.CONCEALED, FfiFieldType.PASSWORD, FfiFieldType.URL, FfiFieldType.EMAIL,
        FfiFieldType.PHONE, FfiFieldType.MENU, FfiFieldType.OTP, FfiFieldType.MNEMONIC,
    )

    private fun textValue(kind: FfiFieldType, text: String): FfiFieldValue = if (text.isEmpty()) FfiFieldValue.Empty else when (kind) {
        FfiFieldType.TEXT -> FfiFieldValue.Text(text)
        FfiFieldType.CONCEALED -> FfiFieldValue.Concealed(text)
        FfiFieldType.PASSWORD -> FfiFieldValue.Password(text)
        FfiFieldType.URL -> FfiFieldValue.Url(text)
        FfiFieldType.EMAIL -> FfiFieldValue.Email(text)
        FfiFieldType.PHONE -> FfiFieldValue.Phone(text)
        FfiFieldType.MENU -> FfiFieldValue.Menu(text)
        FfiFieldType.OTP -> FfiFieldValue.Otp(text)
        else -> FfiFieldValue.Mnemonic(text)
    }

    private fun watch(e: EditText, on: () -> Unit) = e.addTextChangedListener(object : TextWatcher {
        override fun afterTextChanged(x: Editable?) = on()
        override fun beforeTextChanged(x: CharSequence?, a: Int, b: Int, c: Int) {}
        override fun onTextChanged(x: CharSequence?, a: Int, b: Int, c: Int) {}
    })

    /** The editor ("Nouvel élément" / "Modification"), built once so a redraw keeps what is typed. */
    fun edit(item: FfiItem, isNew: Boolean) {
        val s = a.vault.session ?: return a.route()
        val cat = Category.of(item.itemType)
        val inputs = mutableMapOf<String, Pair<FfiFieldType, EditText>>()
        val changed = mutableSetOf<String>()
        val title = ui.field(cat.singular(a), item.title).apply { textSize = 22f; typeface = Typeface.create(Typeface.DEFAULT, 600, false) }
        val url = ui.field("https://", item.urls.firstOrNull { it.primary }?.url ?: item.urls.firstOrNull()?.url ?: "").apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
        }
        val notes = ui.field(a.t("Notes", "Notes"), item.notes).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_CAP_SENTENCES
            minLines = 3
            gravity = Gravity.TOP
        }
        val tags = ui.field(a.t("Tags, séparés par des virgules", "Tags, comma separated"), item.tags.joinToString(", "))
        val err = ui.footnote("", ui.red)

        fun labeled(label: String, input: View, trailing: View? = null): View {
            val row = LinearLayout(a).apply { gravity = Gravity.CENTER_VERTICAL; setPadding(0, ui.dp(8), ui.dp(8), 0) }
            val col = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL }
            col.addView(ui.text(label, 13f, ui.readableAccent, 500).apply { setPadding(ui.dp(16), 0, ui.dp(16), 0) })
            col.addView(input.apply { (this as? EditText)?.setPadding(ui.dp(16), ui.dp(4), ui.dp(16), ui.dp(10)) })
            row.addView(col, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            trailing?.let { row.addView(it) }
            // Touching the row (its label) puts the cursor in the field, as on iPhone.
            (input as? EditText)?.let { e ->
                row.setOnClickListener {
                    e.requestFocus()
                    a.getSystemService(android.view.inputmethod.InputMethodManager::class.java).showSoftInput(e, 0)
                }
            }
            return row
        }

        val save = save@{
            val updated = item.copy(
                title = title.text.toString().trim(),
                notes = notes.text.toString(),
                tags = tags.text.toString().split(",").map { it.trim() }.filter { it.isNotEmpty() }.distinct(),
                urls = url.text.toString().trim().let { u ->
                    val others = item.urls.filter { !it.primary }
                    if (u.isEmpty()) others else listOf(FfiUrl("", u, FfiMatchRule.DOMAIN, true)) + others
                },
                sections = item.sections.map { sec ->
                    sec.copy(fields = sec.fields.map { f ->
                        val input = inputs[f.id]
                        if (input != null && f.id in changed) f.copy(value = textValue(f.kind, input.second.text.toString())) else f
                    })
                },
            )
            a.background({ s.saveItem(updated) }) { r ->
                r.onSuccess { saved ->
                    a.changed {
                        a.pop()
                        if (!isNew) a.pop()
                        a.push { detailPage(saved) }
                    }
                }.onFailure { e ->
                    err.text = if (e is me.somalabs.onepass.core.OnePassException.Validation) {
                        val label = item.sections.flatMap { it.fields }.firstOrNull { it.id == e.field }?.label ?: e.field
                        a.t("« $label » est obligatoire.", "“$label” is required.")
                    } else a.message(e)
                }
            }
        }

        val page = a.pushedPage(
            if (isNew) a.t("Nouvel élément", "New Item") else a.t("Modification", "Editing"),
            trailing = listOf(a.barText(a.t("Enregistrer", "Save"), bold = true) { save() }),
        ) {
            val head = LinearLayout(a).apply { gravity = Gravity.CENTER_VERTICAL; setPadding(ui.dp(16), ui.dp(4), 0, ui.dp(4)) }
            head.addView(a.itemIcon(item.itemType, 44))
            head.addView(title, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            addView(ui.inset(ui.card(head), top = Ios.Space.S))

            for (sec in item.sections) {
                val rows = sec.fields.filter { it.kind in textKinds }.map { f ->
                    val secret = isSecret(f.kind) && f.kind != FfiFieldType.OTP
                    val has = f.value !is FfiFieldValue.Empty
                    val input = ui.field(if (secret && has) a.t("Inchangé", "Unchanged") else f.label, if (secret) "" else display(f.value) ?: "", password = secret).apply {
                        if (f.kind == FfiFieldType.EMAIL) inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS
                        if (f.kind == FfiFieldType.PHONE) inputType = InputType.TYPE_CLASS_PHONE
                    }
                    watch(input) { changed.add(f.id) }
                    inputs[f.id] = f.kind to input
                    if (f.kind == FfiFieldType.PASSWORD) {
                        labeled(f.label, input, a.barIcon(R.drawable.ic_wand, a.t("Générer un mot de passe", "Generate Password")) {
                            generator { p ->
                                input.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
                                input.typeface = Typeface.MONOSPACE
                                input.setText(p)
                            }
                        })
                    } else labeled(f.label, input)
                }
                if (rows.isEmpty()) continue
                addView(ui.capsLabel(sec.label.ifBlank { cat.singular(a) }))
                addView(ui.inset(ui.card(*rows.toTypedArray())))
            }
            addView(ui.capsLabel(a.t("Site web", "Website")))
            addView(ui.inset(ui.card(labeled(a.t("site web", "website"), url))))
            addView(ui.capsLabel(a.t("Notes", "Notes")))
            addView(ui.inset(ui.card(notes)))
            addView(ui.capsLabel("Tags"))
            addView(ui.inset(ui.card(tags)))
            addView(err)
        }
        a.push(tabs = false) { (page.parent as? ViewGroup)?.removeView(page); page }
        if (isNew) title.requestFocus()
    }

    // ---- generator -------------------------------------------------------------------------------------------

    /** The password generator sheet: Caractères 8–100 (20), Mots 3–10 (5), PIN 4–12. */
    fun generator(into: ((String) -> Unit)?) {
        var mode = 0
        val lengths = intArrayOf(20, 5, 6)
        val ranges = listOf(8..100, 3..10, 4..12)
        var digits = true
        var symbols = true
        var capitalize = true
        val out = ui.text("", 22f, ui.label, 500).apply {
            typeface = Typeface.MONOSPACE
            gravity = Gravity.CENTER
            setPadding(ui.dp(16), ui.dp(24), ui.dp(16), ui.dp(8))
            minHeight = ui.dp(110)
        }
        val meter = LinearLayout(a).apply { gravity = Gravity.CENTER; setPadding(0, 0, 0, ui.dp(16)) }
        val lenLabel = ui.text("", 17f, ui.label)
        val options = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL }
        var value = ""
        val seek = SeekBar(a).apply {
            progressTintList = ColorStateList.valueOf(ui.accent)
            thumbTintList = ColorStateList.valueOf(ui.accent)
            progressBackgroundTintList = ColorStateList.valueOf(ui.tertiary)
        }
        fun recipe(): FfiPasswordRecipe = when (mode) {
            0 -> FfiPasswordRecipe.Characters(lengths[0].toUInt(), digits, symbols, false)
            1 -> FfiPasswordRecipe.Words(lengths[1].toUInt(), "-", a.t("fr", "en") == "fr", capitalize)
            else -> FfiPasswordRecipe.Pin(lengths[2].toUInt())
        }
        fun regen() {
            val r = recipe()
            value = runCatching { generatePassword(r) }.getOrElse { a.message(it) }
            out.text = colored(value)
            val bits = passwordEntropyBits(r)
            val (label, color) = strengthLabel(bits)
            meter.removeAllViews()
            meter.addView(strengthMeter(label, color, bits))
            lenLabel.text = when (mode) { 0 -> a.t("${lengths[0]} caractères", "${lengths[0]} characters"); 1 -> a.t("${lengths[1]} mots", "${lengths[1]} words"); else -> a.t("${lengths[2]} chiffres", "${lengths[2]} digits") }
        }
        fun drawOptions() {
            options.removeAllViews()
            val range = ranges[mode]
            seek.setOnSeekBarChangeListener(null)
            seek.max = range.last - range.first
            seek.progress = lengths[mode] - range.first
            seek.setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
                override fun onProgressChanged(b: SeekBar?, p: Int, user: Boolean) { lengths[mode] = range.first + p; regen() }
                override fun onStartTrackingTouch(b: SeekBar?) {}
                override fun onStopTrackingTouch(b: SeekBar?) {}
            })
            (seek.parent as? ViewGroup)?.removeView(seek)
            (lenLabel.parent as? ViewGroup)?.removeView(lenLabel)
            val lenRow = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL; setPadding(ui.dp(16), ui.dp(12), ui.dp(16), ui.dp(8)) }
            lenRow.addView(lenLabel)
            lenRow.addView(seek)
            val rows = mutableListOf<View>(lenRow)
            when (mode) {
                0 -> {
                    rows += ui.toggleRow(a.t("Chiffres", "Numbers"), on = digits) { digits = it; regen() }
                    rows += ui.toggleRow(a.t("Symboles", "Symbols"), on = symbols) { symbols = it; regen() }
                }
                1 -> rows += ui.toggleRow(a.t("Majuscules", "Capitalize"), on = capitalize) { capitalize = it; regen() }
            }
            options.addView(ui.inset(ui.card(*rows.toTypedArray())))
        }
        val segments = LinearLayout(a).apply {
            background = ui.rounded(ui.fill, 9)
            setPadding(ui.dp(2), ui.dp(2), ui.dp(2), ui.dp(2))
        }
        fun drawSegments() {
            segments.removeAllViews()
            listOf(a.t("Caractères", "Characters"), a.t("Mots", "Words"), "PIN").forEachIndexed { i, label ->
                segments.addView(ui.text(label, 14f, ui.label, if (i == mode) 600 else 400).apply {
                    gravity = Gravity.CENTER
                    setPadding(0, ui.dp(7), 0, ui.dp(7))
                    if (i == mode) { background = ui.rounded(if (ui.dark) Color.rgb(0x63, 0x63, 0x66) else Color.WHITE, 7); elevation = ui.dp(1).toFloat() }
                    isClickable = true
                    setOnClickListener { mode = i; drawSegments(); drawOptions(); regen() }
                }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            }
        }
        drawSegments()
        drawOptions()
        regen()
        a.sheet(a.t("Générateur", "Generator"), a.t("Fermer", "Close"), into?.let { use -> a.t("Utiliser", "Use") to { d: Dialog -> use(value); d.dismiss() } }) { _ ->
            val col = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL; setPadding(0, ui.dp(8), 0, ui.dp(40)) }
            col.addView(segments, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { setMargins(ui.dp(16), 0, ui.dp(16), 0) })
            val card = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL; background = ui.rounded(ui.card, Ios.Radius.CARD, ui.hairline) }
            card.addView(out)
            card.addView(meter)
            col.addView(ui.inset(card, top = Ios.Space.L))
            val buttons = LinearLayout(a).apply { setPadding(ui.dp(16), ui.dp(12), ui.dp(16), 0) }
            buttons.addView(ui.capsule(a.t("Régénérer", "Regenerate"), prominent = false) { regen() }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { marginEnd = ui.dp(6) })
            buttons.addView(ui.capsule(a.t("Copier", "Copy")) { a.copy(value, true) }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { marginStart = ui.dp(6) })
            col.addView(buttons)
            col.addView(View(a), LinearLayout.LayoutParams(1, ui.dp(16)))
            col.addView(options)
            col
        }
    }
}
