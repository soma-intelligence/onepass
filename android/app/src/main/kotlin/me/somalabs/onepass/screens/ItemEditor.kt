package me.somalabs.onepass.screens

import android.app.DatePickerDialog
import android.app.Dialog
import android.graphics.Color
import android.graphics.Typeface
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.GridLayout
import android.widget.LinearLayout
import android.widget.NumberPicker
import android.widget.ScrollView
import android.widget.TextView
import java.text.DateFormat
import java.util.Calendar
import java.util.GregorianCalendar
import me.somalabs.onepass.MainActivity
import me.somalabs.onepass.R
import me.somalabs.onepass.core.FfiAddress
import me.somalabs.onepass.core.FfiDate
import me.somalabs.onepass.core.FfiField
import me.somalabs.onepass.core.FfiFieldType
import me.somalabs.onepass.core.FfiFieldValue
import me.somalabs.onepass.core.FfiItem
import me.somalabs.onepass.core.FfiMatchRule
import me.somalabs.onepass.core.FfiSection
import me.somalabs.onepass.core.FfiUrl
import me.somalabs.onepass.core.OnePassException
import me.somalabs.onepass.core.menuOptions
import me.somalabs.onepass.ui.Category
import me.somalabs.onepass.ui.Ios

/**
 * The item editor, as on iPhone (ItemEditorView, ItemDraft): title, the
 * template sections with the fields that matter shown and the others folded
 * behind "ajouter plus", "+ ajouter …" under repeatable fields, custom fields
 * (label and value, removable) in "Champs perso", websites, notes, tags,
 * then vault, favorite, confirmation and Travel Mode options.
 *
 * Every kind has its control: text, secrets (masked, revealable, generator
 * for passwords), dates and month-year (pickers), numbers, money, addresses,
 * menus (the core's options), item links, barcodes. Passkeys, files, SSH keys
 * and places are shown read only, as on iPhone (a site adds a passkey, files
 * are attachments, an SSH key is generated or imported).
 *
 * The draft lives here; the views are rebuilt from it when a row is added or
 * removed, so nothing typed is lost.
 */
class ItemEditor(private val a: MainActivity, private val original: FfiItem, private val isNew: Boolean) {
    private val ui get() = a.ui
    private val cat = Category.of(original.itemType)

    private class Row(val key: Int, var field: FfiField)
    private class Sec(val id: String, val label: String, val rows: MutableList<Row>)

    private var nextKey = 0
    private val sections: MutableList<Sec> = original.sections.map { s ->
        Sec(s.id, s.label, s.fields.map { Row(nextKey++, it) }.toMutableList())
    }.toMutableList()
    private var title = original.title
    private var notes = original.notes
    private val urls: MutableList<FfiUrl> = original.urls.toMutableList()
    private val tags: MutableList<String> = original.tags.toMutableList()
    private var favorite = original.favorite
    private var reprompt = original.reprompt
    private var travelHidden = original.travelHidden
    private var travelGuard = original.travelGuard
    private var vaultId = original.vaultId
    private var showAll = false
    private val pinned = mutableSetOf<Int>()
    private var error: String? = null
    private var errorField: String? = null

    private lateinit var body: LinearLayout
    private lateinit var scroll: ScrollView
    private var titleInput: EditText? = null

    init {
        sections.forEachIndexed { si, sec ->
            sec.rows.forEachIndexed { fi, r ->
                if (essential(r.field, sec.id, si == 0 && fi < 3)) pinned.add(r.key)
            }
        }
        if (urls.isEmpty()) urls.add(FfiUrl("", "", FfiMatchRule.DOMAIN, true))
    }

    /** Required and filled fields, and the first three of the first section; custom fields always. */
    private fun essential(f: FfiField, sectionId: String, leading: Boolean): Boolean {
        if (sectionId == CUSTOM) return true
        if (f.kind == FfiFieldType.PASSKEY) return f.value !is FfiFieldValue.Empty
        return f.required || f.value !is FfiFieldValue.Empty || leading
    }

    fun open() {
        val page = a.pushedPage(
            if (isNew) a.t("Nouvel élément", "New Item") else a.t("Modification", "Editing"),
            trailing = listOf(a.barText(a.t("Enregistrer", "Save"), bold = true) { save() }),
        ) {
            body = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL }
            addView(body)
        } as ScrollView
        scroll = page
        redraw()
        a.push(tabs = false, guard = { leave -> cancel(leave) }) { (page.parent as? ViewGroup)?.removeView(page); page }
        if (isNew) titleInput?.requestFocus()
    }

    // ---- the draft -------------------------------------------------------------------------------

    private fun build(): FfiItem {
        val out = original.copy(
            title = title.trim(),
            notes = notes,
            tags = tags.toList(),
            favorite = favorite,
            reprompt = reprompt,
            travelHidden = travelHidden,
            travelGuard = travelGuard && !travelHidden,
            sections = sections.map { s ->
                FfiSection(s.id, s.label, s.rows.map { r ->
                    if (s.id == CUSTOM && r.field.label.isBlank()) r.field.copy(label = defaultLabel(r.field.kind)) else r.field
                })
            },
        )
        var list = urls.map { it.copy(url = it.url.trim(), label = it.label.trim()) }.filter { it.url.isNotEmpty() }
        if (list.isNotEmpty() && list.count { it.primary } != 1) {
            val first = list.indexOfFirst { it.primary }.coerceAtLeast(0)
            list = list.mapIndexed { i, u -> u.copy(primary = i == first) }
        }
        out.urls = list
        return out
    }

    private val dirty get() = build() != original || vaultId != original.vaultId

    private fun cancel(leave: () -> Unit) {
        if (!dirty) return leave()
        a.confirm(a.t("Abandonner les modifications ?", "Discard changes?"), a.t("Abandonner", "Discard")) { leave() }
    }

    private fun setValue(row: Row, v: FfiFieldValue) {
        row.field = row.field.copy(value = normalized(v))
        if (errorField == row.field.id) errorField = null
    }

    private fun normalized(v: FfiFieldValue): FfiFieldValue = when (v) {
        is FfiFieldValue.Text -> if (v.value.isEmpty()) FfiFieldValue.Empty else v
        is FfiFieldValue.Concealed -> if (v.value.isEmpty()) FfiFieldValue.Empty else v
        is FfiFieldValue.Password -> if (v.value.isEmpty()) FfiFieldValue.Empty else v
        is FfiFieldValue.Url -> if (v.value.isEmpty()) FfiFieldValue.Empty else v
        is FfiFieldValue.Email -> if (v.value.isEmpty()) FfiFieldValue.Empty else v
        is FfiFieldValue.Phone -> if (v.value.isEmpty()) FfiFieldValue.Empty else v
        is FfiFieldValue.Menu -> if (v.value.isEmpty()) FfiFieldValue.Empty else v
        is FfiFieldValue.Otp -> if (v.value.isEmpty()) FfiFieldValue.Empty else v
        is FfiFieldValue.Mnemonic -> if (v.value.isEmpty()) FfiFieldValue.Empty else v
        is FfiFieldValue.Address -> v.value.let { ad -> if (listOf(ad.line1, ad.line2, ad.city, ad.postalCode, ad.region, ad.country).all { it.isEmpty() }) FfiFieldValue.Empty else v }
        is FfiFieldValue.Barcode -> if (v.value.isEmpty()) FfiFieldValue.Empty else v
        is FfiFieldValue.ItemLink -> if (v.itemId.isEmpty()) FfiFieldValue.Empty else v
        else -> v
    }

    private fun text(v: FfiFieldValue): String = when (v) {
        is FfiFieldValue.Text -> v.value
        is FfiFieldValue.Concealed -> v.value
        is FfiFieldValue.Password -> v.value
        is FfiFieldValue.Url -> v.value
        is FfiFieldValue.Email -> v.value
        is FfiFieldValue.Phone -> v.value
        is FfiFieldValue.Menu -> v.value
        is FfiFieldValue.Otp -> v.value
        is FfiFieldValue.Mnemonic -> v.value
        else -> ""
    }

    private fun fromText(kind: FfiFieldType, s: String): FfiFieldValue = if (s.isEmpty()) FfiFieldValue.Empty else when (kind) {
        FfiFieldType.CONCEALED -> FfiFieldValue.Concealed(s)
        FfiFieldType.PASSWORD -> FfiFieldValue.Password(s)
        FfiFieldType.URL -> FfiFieldValue.Url(s)
        FfiFieldType.EMAIL -> FfiFieldValue.Email(s)
        FfiFieldType.PHONE -> FfiFieldValue.Phone(s)
        FfiFieldType.MENU -> FfiFieldValue.Menu(s)
        FfiFieldType.OTP -> FfiFieldValue.Otp(s)
        FfiFieldType.MNEMONIC -> FfiFieldValue.Mnemonic(s)
        else -> FfiFieldValue.Text(s)
    }

    private fun defaultLabel(kind: FfiFieldType) = when (kind) {
        FfiFieldType.CONCEALED -> a.t("Champ masqué", "Hidden field")
        FfiFieldType.PASSWORD -> a.t("Mot de passe", "Password")
        FfiFieldType.DATE -> "Date"
        FfiFieldType.URL -> a.t("Site web", "Website")
        FfiFieldType.EMAIL -> "Email"
        FfiFieldType.PHONE -> a.t("Téléphone", "Phone")
        else -> a.t("Texte", "Text")
    }

    /** Removable: a custom field, or a repeated copy (not the first of its id). */
    private fun removable(sec: Sec, i: Int): Boolean =
        sec.id == CUSTOM || sec.rows.subList(0, i).any { it.field.id == sec.rows[i].field.id }

    /** "+ ajouter …" goes under the last copy of a repeatable field. */
    private fun canRepeat(sec: Sec, i: Int): Boolean {
        val f = sec.rows[i].field
        return f.repeatable && sec.rows.indexOfLast { it.field.id == f.id } == i && f.kind != FfiFieldType.PASSKEY && f.kind != FfiFieldType.FILE
    }

    private fun addRepeat(sec: Sec, i: Int) {
        val copy = sec.rows[i].field.copy(value = FfiFieldValue.Empty, required = false)
        val r = Row(nextKey++, copy)
        sec.rows.add(i + 1, r)
        pinned.add(r.key)
        redraw()
    }

    private fun addCustom(kind: FfiFieldType) {
        val sec = sections.firstOrNull { it.id == CUSTOM } ?: Sec(CUSTOM, "Champs perso", mutableListOf()).also { sections.add(it) }
        fun num(id: String) = id.removePrefix(PREFIX).takeIf { id.startsWith(PREFIX) }?.toIntOrNull()
        val used = sections.flatMap { it.rows }.mapNotNull { num(it.field.id) }
        val before = original.sections.flatMap { it.fields }.mapNotNull { num(it.id) }
        val next = maxOf(used.maxOrNull() ?: 0, before.maxOrNull() ?: 0) + 1
        val r = Row(nextKey++, FfiField(PREFIX + next, defaultLabel(kind), kind, FfiFieldValue.Empty, false, false, false))
        sec.rows.add(r)
        pinned.add(r.key)
        redraw()
    }

    private fun visible(sec: Sec, r: Row) = showAll || sec.id == CUSTOM || r.key in pinned || r.field.id == errorField

    // ---- save ---------------------------------------------------------------------------------------

    private fun save() {
        val s = a.vault.session ?: return a.route()
        val updated = build()
        val target = vaultId
        a.background({
            val saved = s.saveItem(updated)
            if (target != saved.vaultId) {
                s.moveItem(saved.id, saved.vaultId, target)
                s.item(target, saved.id)
            } else saved
        }) { r ->
            r.onSuccess { saved ->
                a.changed {
                    a.popNow()
                    if (!isNew) a.popNow()
                    a.items.showSaved(saved)
                }
            }.onFailure { e ->
                if (e is OnePassException.Validation) {
                    errorField = e.field
                    val label = if (e.field == "title") a.t("Titre", "Title") else sections.flatMap { it.rows }.firstOrNull { it.field.id == e.field }?.field?.label ?: e.field
                    error = a.t("« $label » est obligatoire ou incorrect.", "“$label” is required or invalid.")
                } else error = a.message(e)
                redraw()
                scroll.post { scroll.smoothScrollTo(0, 0) }
            }
        }
    }

    // ---- page ---------------------------------------------------------------------------------------

    private fun watch(e: EditText, on: (String) -> Unit) = e.addTextChangedListener(object : TextWatcher {
        override fun afterTextChanged(x: Editable?) = on(x?.toString() ?: "")
        override fun beforeTextChanged(x: CharSequence?, s: Int, c: Int, b: Int) {}
        override fun onTextChanged(x: CharSequence?, s: Int, b: Int, c: Int) {}
    })

    private fun label(s: String, color: Int = ui.readableAccent) = ui.text(s, 13f, color, 500)

    /** A row: the label in the accent above the control, an optional trailing view. */
    private fun row(labelView: View, control: View, trailing: View? = null, message: String? = null): View {
        val row = LinearLayout(a).apply { gravity = Gravity.CENTER_VERTICAL; setPadding(ui.dp(16), ui.dp(10), ui.dp(6), ui.dp(8)) }
        val col = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL }
        col.addView(labelView)
        col.addView(control, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = ui.dp(4) })
        message?.let { col.addView(ui.text(it, 13f, ui.red).apply { setPadding(0, ui.dp(4), 0, 0) }) }
        row.addView(col, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        trailing?.let { row.addView(it) }
        (control as? EditText)?.let { e ->
            row.setOnClickListener {
                e.requestFocus()
                a.getSystemService(android.view.inputmethod.InputMethodManager::class.java).showSoftInput(e, 0)
            }
        }
        return row
    }

    private fun input(hint: String, value: String, type: Int = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS) =
        ui.field(hint, value).apply {
            inputType = type
            setPadding(0, ui.dp(2), 0, ui.dp(2))
        }

    private fun removeButton(desc: String, onClick: () -> Unit) = FrameLayout(a).apply {
        contentDescription = desc
        isClickable = true
        setPadding(ui.dp(10), ui.dp(10), ui.dp(10), ui.dp(10))
        addView(FrameLayout(a).apply {
            background = android.graphics.drawable.GradientDrawable().apply { shape = android.graphics.drawable.GradientDrawable.OVAL; setColor(ui.red) }
            addView(View(a).apply { setBackgroundColor(Color.WHITE) }, FrameLayout.LayoutParams(ui.dp(10), ui.dp(2), Gravity.CENTER))
        }, FrameLayout.LayoutParams(ui.dp(22), ui.dp(22)))
        setOnClickListener { onClick() }
    }

    private fun addRow(title: String, onClick: () -> Unit): View = LinearLayout(a).apply {
        gravity = Gravity.CENTER_VERTICAL
        minimumHeight = ui.dp(48)
        setPadding(ui.dp(16), ui.dp(10), ui.dp(16), ui.dp(10))
        background = ui.pressable(null)
        isClickable = true
        setOnClickListener { onClick() }
        addView(ui.glyph(R.drawable.ic_add, ui.accent, 20))
        addView(ui.text(title, 17f, ui.readableAccent, 500).apply { setPadding(ui.dp(10), 0, 0, 0) })
    }

    private fun redraw() {
        body.removeAllViews()
        // Title.
        val head = LinearLayout(a).apply { gravity = Gravity.CENTER_VERTICAL; setPadding(ui.dp(16), ui.dp(4), 0, ui.dp(4)) }
        head.addView(a.itemIcon(original.itemType, 44))
        val t = ui.field(cat.singular(a), title).apply { textSize = 22f; typeface = ui.font(600); inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_SENTENCES }
        watch(t) { title = it; if (errorField == "title") errorField = null }
        titleInput = t
        head.addView(t, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        body.addView(ui.inset(ui.card(head), top = Ios.Space.S))
        error?.let { body.addView(ui.footnote(it, ui.red)) }

        // Sections.
        for (sec in sections) {
            val rows = mutableListOf<View>()
            sec.rows.forEachIndexed { i, r ->
                if (!visible(sec, r)) return@forEachIndexed
                rows += fieldRow(sec, i, r)
                if (canRepeat(sec, i)) rows += addRow(a.t("ajouter ", "add ") + lowerFirst(r.field.label)) { addRepeat(sec, i) }
            }
            if (rows.isEmpty()) continue
            if (sections.size > 1 || sec.id == CUSTOM) {
                body.addView(ui.capsLabel(if (sec.id == CUSTOM) a.t("Champs perso", "Custom fields") else sec.label.ifBlank { cat.singular(a) }))
            } else body.addView(View(a), LinearLayout.LayoutParams(1, ui.dp(16)))
            body.addView(ui.inset(ui.card(*rows.toTypedArray())))
        }

        // Websites and "ajouter plus".
        val webRows = mutableListOf<View>()
        urls.forEachIndexed { i, u ->
            val e = input("https://", u.url, InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI)
            watch(e) { urls[i] = urls[i].copy(url = it) }
            val lbl = if (urls.size > 1 && u.primary) a.t("site web principal", "primary website") else a.t("site web", "website")
            webRows += row(label(lbl), e, removeButton(a.t("Retirer ce site web", "Remove This Website")) {
                val wasPrimary = urls[i].primary
                urls.removeAt(i)
                if (wasPrimary && urls.isNotEmpty()) urls[0] = urls[0].copy(primary = true)
                redraw()
            })
        }
        webRows += addRow(if (urls.isEmpty()) a.t("ajouter un site web", "add a website") else a.t("ajouter un autre site web", "add another website")) {
            urls.add(FfiUrl("", "", FfiMatchRule.DOMAIN, urls.isEmpty()))
            redraw()
        }
        webRows += addRow(a.t("ajouter plus", "add more")) { addMore() }
        body.addView(View(a), LinearLayout.LayoutParams(1, ui.dp(16)))
        body.addView(ui.inset(ui.card(*webRows.toTypedArray())))

        // Notes.
        val n = ui.field(a.t("Ajoute des notes sur cet élément.", "Add notes about this item."), notes).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_CAP_SENTENCES
            minLines = 3
            gravity = Gravity.TOP
            setPadding(0, ui.dp(2), 0, ui.dp(2))
        }
        watch(n) { notes = it }
        body.addView(View(a), LinearLayout.LayoutParams(1, ui.dp(16)))
        body.addView(ui.inset(ui.card(row(label(a.t("notes", "notes")), n))))

        // Tags.
        body.addView(ui.capsLabel("Tags"))
        body.addView(ui.inset(ui.card(tagEditor())))

        // Options.
        val vaultName = a.vaults.firstOrNull { it.id == vaultId }?.meta?.name ?: ""
        val options = mutableListOf<View>()
        options += ui.row(title = a.t("Coffre", "Vault"), value = vaultName, chevron = a.vaults.size > 1, onClick = if (a.vaults.size > 1) ({ pickVault() }) else null)
        options += ui.toggleRow(a.t("Favori", "Favorite"), on = favorite) { favorite = it }
        options += ui.toggleRow(a.t("Confirmer avant d'afficher", "Confirm Before Showing"), on = reprompt) { reprompt = it }
        body.addView(View(a), LinearLayout.LayoutParams(1, ui.dp(24)))
        body.addView(ui.inset(ui.card(*options.toTypedArray())))
        lateinit var guardRow: LinearLayout
        val hiddenRow = ui.toggleRow(a.t("Caché en voyage", "Hidden in Travel Mode"), on = travelHidden) {
            travelHidden = it
            guardRow.alpha = if (it) 0.4f else 1f
            guardRow.getChildAt(guardRow.childCount - 1).isEnabled = !it
            travelFooter?.text = travelText()
        }
        guardRow = ui.toggleRow(a.t("Protection renforcée en voyage", "Extra Protection in Travel Mode"), on = travelGuard) { travelGuard = it }
        guardRow.alpha = if (travelHidden) 0.4f else 1f
        guardRow.getChildAt(guardRow.childCount - 1).isEnabled = !travelHidden
        body.addView(ui.inset(ui.card(hiddenRow, guardRow), top = Ios.Space.L))
        travelFooter = ui.footnote(travelText())
        body.addView(travelFooter)
    }

    private var travelFooter: TextView? = null

    private fun travelText() = if (travelHidden) a.t("Quitte cet appareil en Travel Mode et revient vérifié au retour.", "Leaves this device in Travel Mode and comes back verified when you return.")
    else a.t("En Travel Mode, Caché le retire de l'appareil et Protection renforcée demande le mot de passe maître et la biométrie.", "In Travel Mode, Hidden removes it from the device and Extra Protection asks for the master password and biometrics.")

    private fun lowerFirst(s: String): String {
        if (s.length < 2) return s.lowercase()
        return if (s[0].isUpperCase() && !s[1].isUpperCase()) s[0].lowercase() + s.substring(1) else s
    }

    private fun pickVault() {
        val list = a.vaults
        android.app.AlertDialog.Builder(a).setTitle(a.t("Coffre", "Vault"))
            .setSingleChoiceItems(list.map { it.meta.name }.toTypedArray(), list.indexOfFirst { it.id == vaultId }) { d, i ->
                vaultId = list[i].id
                d.dismiss()
                redraw()
            }.show()
    }

    // ---- tags -------------------------------------------------------------------------------------------

    private fun tagEditor(): View {
        val col = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL; setPadding(ui.dp(12), ui.dp(10), ui.dp(12), ui.dp(6)) }
        if (tags.isNotEmpty()) {
            val chips = LinearLayout(a)
            tags.toList().forEach { tag ->
                val chip = LinearLayout(a).apply {
                    gravity = Gravity.CENTER_VERTICAL
                    background = ui.rounded(Color.argb(if (ui.dark) 0x40 else 0x1F, Color.red(ui.accent), Color.green(ui.accent), Color.blue(ui.accent)), 9)
                    setPadding(ui.dp(12), ui.dp(6), ui.dp(6), ui.dp(6))
                    contentDescription = a.t("Retirer le tag $tag", "Remove Tag $tag")
                    isClickable = true
                    setOnClickListener { tags.remove(tag); redraw() }
                }
                chip.addView(ui.text(tag, 15f, ui.label, 500))
                chip.addView(ui.glyph(R.drawable.ic_close, ui.secondary, 16).apply { (layoutParams as LinearLayout.LayoutParams).marginStart = ui.dp(4) })
                chips.addView(chip, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { marginEnd = ui.dp(8) })
            }
            col.addView(android.widget.HorizontalScrollView(a).apply { isHorizontalScrollBarEnabled = false; addView(chips) })
        }
        val e = ui.field(a.t("Ajouter un tag", "Add Tag")).apply {
            setPadding(ui.dp(4), ui.dp(10), ui.dp(4), ui.dp(8))
            imeOptions = EditorInfo.IME_ACTION_DONE or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
        }
        fun commit() {
            val parts = e.text.toString().split(",").map { it.trim() }.filter { it.isNotEmpty() }
            var added = false
            parts.forEach { p -> if (tags.none { it.equals(p, ignoreCase = true) }) { tags.add(p); added = true } }
            if (added || parts.isNotEmpty()) redraw()
        }
        e.setOnEditorActionListener { _, _, _ -> commit(); true }
        val known = a.summaries.flatMap { it.tags }.distinct().filter { k -> tags.none { it.equals(k, true) } }.sorted()
        val line = LinearLayout(a).apply { gravity = Gravity.CENTER_VERTICAL }
        line.addView(e, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        line.addView(a.barIcon(R.drawable.ic_add, a.t("Ajouter un tag", "Add Tag")) {
            if (e.text.isNotBlank()) commit()
            else if (known.isNotEmpty()) android.app.AlertDialog.Builder(a).setTitle(a.t("Ajouter un tag", "Add Tag"))
                .setItems(known.toTypedArray()) { _, i -> tags.add(known[i]); redraw() }.show()
        })
        col.addView(line)
        return col
    }

    // ---- "ajouter plus" --------------------------------------------------------------------------------

    private val customKinds = listOf(
        FfiFieldType.TEXT to (a.t("Texte", "Text") to R.drawable.ic_edit),
        FfiFieldType.CONCEALED to (a.t("Masqué", "Hidden") to R.drawable.ic_eye_off),
        FfiFieldType.PASSWORD to (a.t("Mot de passe", "Password") to R.drawable.ic_key),
        FfiFieldType.DATE to ("Date" to R.drawable.ic_calendar_alert),
        FfiFieldType.URL to ("URL" to R.drawable.ic_link),
        FfiFieldType.EMAIL to ("Email" to R.drawable.ic_globe),
        FfiFieldType.PHONE to (a.t("Téléphone", "Phone") to R.drawable.ic_number),
    )

    /** The folded template fields (with "Tout afficher") and the custom field kinds, with a search. */
    private fun addMore() {
        val hidden = sections.flatMap { sec -> sec.rows.filter { !visible(sec, it) && it.field.kind != FfiFieldType.PASSKEY && it.field.kind != FfiFieldType.FILE } }
        a.sheet(a.t("ajouter plus", "add more").replaceFirstChar { it.uppercase() }, a.t("Fermer", "Close"), null) { d ->
            val col = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL; setPadding(0, ui.dp(8), 0, ui.dp(40)) }
            val search = ui.searchField(a.t("Rechercher un champ", "Search fields"))
            col.addView(ui.inset(search))
            val list = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL }
            col.addView(list)
            fun draw(q: String) {
                list.removeAllViews()
                val hs = hidden.filter { q.isBlank() || it.field.label.contains(q.trim(), ignoreCase = true) }
                val ks = customKinds.filter { q.isBlank() || it.second.first.contains(q.trim(), ignoreCase = true) }
                if (hs.isNotEmpty()) {
                    val showAllLink = if (hidden.size > 1 && q.isBlank()) a.barText(a.t("Tout afficher", "Show All")) { d.dismiss(); showAll = true; redraw() } else null
                    list.addView(ui.sectionHeader(a.t("Champs du modèle", "Template Fields"), showAllLink))
                    list.addView(ui.inset(ui.card(*hs.map { r ->
                        ui.row(icon = ui.glyph(symbol(r.field), ui.accent, 22), title = r.field.label, chevron = false, trailing = ui.glyph(R.drawable.ic_add, ui.accent, 20)) {
                            d.dismiss(); pinned.add(r.key); redraw()
                        }
                    }.toTypedArray())))
                }
                if (ks.isNotEmpty()) {
                    list.addView(ui.sectionHeader(a.t("Champ personnalisé", "Custom Field")))
                    val grid = GridLayout(a).apply { columnCount = 4; setPadding(ui.dp(12), 0, ui.dp(12), 0) }
                    ks.forEach { (kind, lv) ->
                        val cell = LinearLayout(a).apply {
                            orientation = LinearLayout.VERTICAL
                            gravity = Gravity.CENTER
                            background = ui.pressable(ui.rounded(ui.card, Ios.Radius.CONTROL, ui.hairline), Ios.Radius.CONTROL)
                            setPadding(ui.dp(4), ui.dp(12), ui.dp(4), ui.dp(10))
                            isClickable = true
                            contentDescription = lv.first
                            setOnClickListener { d.dismiss(); addCustom(kind) }
                        }
                        cell.addView(ui.glyph(lv.second, ui.accent, 22))
                        cell.addView(ui.text(lv.first, 12f, ui.label).apply { gravity = Gravity.CENTER; maxLines = 1; setPadding(0, ui.dp(6), 0, 0) })
                        val cellW = (a.resources.displayMetrics.widthPixels - ui.dp(24)) / 4 - ui.dp(8)
                        grid.addView(cell, GridLayout.LayoutParams().apply { width = cellW; setMargins(ui.dp(4), ui.dp(4), ui.dp(4), ui.dp(4)) })
                    }
                    list.addView(grid)
                }
                if (hs.isEmpty() && ks.isEmpty()) list.addView(ui.footnote(a.t("Aucun champ ne correspond.", "No matching field.")).apply { gravity = Gravity.CENTER })
            }
            val e = search.getChildAt(1) as EditText
            watch(e) { draw(it) }
            draw("")
            col
        }
    }

    private fun symbol(f: FfiField): Int = when (f.id) {
        "totp" -> R.drawable.ic_two_factor
        "pin" -> R.drawable.ic_number
        else -> when (f.kind) {
            FfiFieldType.PASSWORD, FfiFieldType.CONCEALED -> R.drawable.ic_key
            FfiFieldType.URL -> R.drawable.ic_link
            FfiFieldType.DATE, FfiFieldType.MONTH_YEAR -> R.drawable.ic_calendar_alert
            FfiFieldType.NUMBER, FfiFieldType.PHONE, FfiFieldType.MONEY -> R.drawable.ic_number
            FfiFieldType.OTP -> R.drawable.ic_two_factor
            FfiFieldType.ADDRESS, FfiFieldType.LOCATION -> R.drawable.ic_home
            FfiFieldType.SSH_KEY -> R.drawable.ic_terminal
            FfiFieldType.ITEM_LINK -> R.drawable.ic_link
            else -> R.drawable.ic_edit
        }
    }

    // ---- one field ------------------------------------------------------------------------------------

    private fun fieldRow(sec: Sec, i: Int, r: Row): View {
        val f = r.field
        val custom = sec.id == CUSTOM
        val labelView: View = if (custom) {
            ui.field(defaultLabel(f.kind), f.label).apply {
                textSize = 13f
                setTextColor(ui.readableAccent)
                setPadding(0, 0, 0, 0)
                watch(this) { r.field = r.field.copy(label = it) }
            }
        } else label(lowerFirst(f.label) + if (f.required) " *" else "")
        val trailing = mutableListOf<View>()
        val control = control(r, trailing)
        if (removable(sec, i)) trailing += removeButton(a.t("Retirer ", "Remove ") + f.label) {
            sec.rows.removeAt(i)
            if (sec.id == CUSTOM && sec.rows.isEmpty()) sections.remove(sec)
            redraw()
        }
        val t = when (trailing.size) {
            0 -> null
            1 -> trailing[0]
            else -> LinearLayout(a).apply { gravity = Gravity.CENTER_VERTICAL; trailing.forEach { addView(it) } }
        }
        return row(labelView, control, t, if (errorField == f.id) error else null)
    }

    /** The control for a field kind (table of spec 6.4). */
    private fun control(r: Row, trailing: MutableList<View>): View {
        val f = r.field
        return when (f.kind) {
            FfiFieldType.TEXT, FfiFieldType.URL, FfiFieldType.EMAIL, FfiFieldType.PHONE -> {
                val type = when (f.kind) {
                    FfiFieldType.URL -> InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
                    FfiFieldType.EMAIL -> InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS
                    FfiFieldType.PHONE -> InputType.TYPE_CLASS_PHONE
                    else -> InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS or InputType.TYPE_TEXT_FLAG_MULTI_LINE
                }
                input(f.label, text(f.value), type).also { e -> watch(e) { setValue(r, fromText(f.kind, it)) } }
            }
            FfiFieldType.CONCEALED, FfiFieldType.PASSWORD, FfiFieldType.OTP, FfiFieldType.MNEMONIC -> secret(r, trailing)
            FfiFieldType.DATE -> picker(r, trailing, (f.value as? FfiFieldValue.Date)?.value?.let {
                DateFormat.getDateInstance(DateFormat.LONG).format(GregorianCalendar(it.year, it.month.toInt() - 1, it.day.toInt()).time)
            }) { pickDate(r) }
            FfiFieldType.MONTH_YEAR -> picker(r, trailing, (f.value as? FfiFieldValue.MonthYear)?.let { "%02d/%04d".format(it.month.toInt(), it.year.toInt()) }) { pickMonthYear(r) }
            FfiFieldType.NUMBER -> input(f.label, (f.value as? FfiFieldValue.Number)?.value?.toString() ?: "", InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_FLAG_SIGNED).also { e ->
                watch(e) { s -> setValue(r, s.toLongOrNull()?.let { FfiFieldValue.Number(it) } ?: FfiFieldValue.Empty) }
            }
            FfiFieldType.MONEY -> money(r)
            FfiFieldType.ADDRESS -> address(r)
            FfiFieldType.MENU -> menu(r, trailing)
            FfiFieldType.BARCODE -> {
                val v = f.value as? FfiFieldValue.Barcode
                input(f.label, v?.value ?: "").also { e ->
                    watch(e) { s -> setValue(r, FfiFieldValue.Barcode(s, v?.format ?: me.somalabs.onepass.core.FfiBarcodeFormat.QR)) }
                }
            }
            FfiFieldType.ITEM_LINK -> itemLink(r, trailing)
            else -> ui.text(a.items.display(f.value) ?: "—", 17f, ui.secondary).apply {
                maxLines = 2
                if (f.kind == FfiFieldType.SSH_KEY) text = (f.value as? FfiFieldValue.SshKey)?.value?.fingerprintSha256 ?: a.t("Aucune clé privée", "No private key")
            }
        }
    }

    private fun secret(r: Row, trailing: MutableList<View>): View {
        val f = r.field
        val multi = f.kind == FfiFieldType.MNEMONIC
        val hiddenType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        val shownType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD or (if (multi) InputType.TYPE_TEXT_FLAG_MULTI_LINE else 0)
        val e = input(f.label, text(f.value), hiddenType)
        watch(e) { setValue(r, fromText(f.kind, it)) }
        var shown = false
        lateinit var eye: View
        eye = a.barIcon(R.drawable.ic_eye, a.t("Révéler", "Reveal")) {
            shown = !shown
            val sel = e.selectionEnd
            e.inputType = if (shown) shownType else hiddenType
            e.typeface = if (shown && f.kind == FfiFieldType.PASSWORD) Typeface.MONOSPACE else ui.font(400)
            e.setSelection(sel.coerceIn(0, e.text.length))
            ((eye as FrameLayout).getChildAt(0) as android.widget.ImageView).setImageResource(if (shown) R.drawable.ic_eye_off else R.drawable.ic_eye)
        }
        trailing += eye
        if (f.kind == FfiFieldType.PASSWORD) trailing += a.barIcon(R.drawable.ic_wand, a.t("Générer un mot de passe", "Generate Password")) {
            a.items.generator { p ->
                shown = true
                e.inputType = shownType
                e.typeface = Typeface.MONOSPACE
                e.setText(p)
            }
        }
        return e
    }

    /** A value chosen in a dialog: the value (or "Choisir…") and a clear button. */
    private fun picker(r: Row, trailing: MutableList<View>, shown: String?, pick: () -> Unit): View {
        if (shown != null) trailing += a.barIcon(R.drawable.ic_close, a.t("Effacer", "Clear")) { setValue(r, FfiFieldValue.Empty); redraw() }
        return ui.text(shown ?: a.t("Choisir…", "Choose…"), 17f, if (shown != null) ui.label else ui.readableAccent).apply {
            setPadding(0, ui.dp(4), 0, ui.dp(4))
            isClickable = true
            setOnClickListener { pick() }
        }
    }

    private fun pickDate(r: Row) {
        val cur = (r.field.value as? FfiFieldValue.Date)?.value
        val now = Calendar.getInstance()
        DatePickerDialog(a, { _, y, m, d ->
            setValue(r, FfiFieldValue.Date(FfiDate(y, (m + 1).toUByte(), d.toUByte())))
            redraw()
        }, cur?.year ?: now.get(Calendar.YEAR), (cur?.month?.toInt() ?: (now.get(Calendar.MONTH) + 1)) - 1, cur?.day?.toInt() ?: now.get(Calendar.DAY_OF_MONTH)).show()
    }

    private fun pickMonthYear(r: Row) {
        val cur = r.field.value as? FfiFieldValue.MonthYear
        val now = Calendar.getInstance()
        val months = java.text.DateFormatSymbols.getInstance().months.take(12).toTypedArray()
        val m = NumberPicker(a).apply { minValue = 1; maxValue = 12; displayedValues = months; value = cur?.month?.toInt() ?: (now.get(Calendar.MONTH) + 1); wrapSelectorWheel = true }
        val y = NumberPicker(a).apply { minValue = 1950; maxValue = 2100; value = cur?.year?.toInt() ?: now.get(Calendar.YEAR); wrapSelectorWheel = false }
        val box = LinearLayout(a).apply { gravity = Gravity.CENTER; setPadding(ui.dp(16), ui.dp(8), ui.dp(16), 0) }
        box.addView(m, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.4f))
        box.addView(y, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        android.app.AlertDialog.Builder(a).setTitle(a.t("Choisir le mois et l'année", "Choose Month and Year")).setView(box)
            .setPositiveButton("OK") { _, _ -> setValue(r, FfiFieldValue.MonthYear(y.value.toUShort(), m.value.toUByte())); redraw() }
            .setNegativeButton(a.t("Annuler", "Cancel"), null).show()
    }

    private fun money(r: Row): View {
        val v = r.field.value as? FfiFieldValue.Money
        var currency = v?.currency ?: if (a.t("fr", "en") == "fr") "EUR" else "USD"
        val amount = input("0,00", v?.let { "%d,%02d".format(it.minorUnits / 100, kotlin.math.abs(it.minorUnits % 100)) } ?: "",
            InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_FLAG_DECIMAL or InputType.TYPE_NUMBER_FLAG_SIGNED)
        amount.keyListener = android.text.method.DigitsKeyListener.getInstance("0123456789,.-")
        val cur = input(a.t("Devise", "Currency"), currency, InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_CHARACTERS).apply {
            filters = arrayOf(android.text.InputFilter.LengthFilter(3), android.text.InputFilter.AllCaps())
            gravity = Gravity.END
        }
        fun update() {
            val txt = amount.text.toString().replace(',', '.').trim()
            if (txt.isEmpty()) { setValue(r, FfiFieldValue.Empty); return }
            val minor = txt.toBigDecimalOrNull()?.movePointRight(2)?.setScale(0, java.math.RoundingMode.HALF_UP)?.toLong() ?: return
            setValue(r, FfiFieldValue.Money(minor, currency))
        }
        watch(amount) { update() }
        watch(cur) { currency = it.uppercase(); update() }
        return LinearLayout(a).apply {
            gravity = Gravity.CENTER_VERTICAL
            addView(amount, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            addView(cur, LinearLayout.LayoutParams(ui.dp(72), ViewGroup.LayoutParams.WRAP_CONTENT))
        }
    }

    private fun address(r: Row): View {
        var ad = (r.field.value as? FfiFieldValue.Address)?.value ?: FfiAddress("", "", "", "", "", "")
        val col = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL }
        fun part(hint: String, value: String, set: (String) -> FfiAddress, type: Int = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_WORDS or InputType.TYPE_TEXT_VARIATION_POSTAL_ADDRESS) {
            val e = input(hint, value, type).apply { setPadding(0, ui.dp(6), 0, ui.dp(6)) }
            watch(e) { ad = set(it); setValue(r, FfiFieldValue.Address(ad)) }
            if (col.childCount > 0) col.addView(View(a).apply { setBackgroundColor(ui.separator) }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, maxOf(1, ui.dp(0.33))))
            col.addView(e)
        }
        part(a.t("Ligne 1", "Line 1"), ad.line1, { ad.copy(line1 = it) })
        part(a.t("Ligne 2", "Line 2"), ad.line2, { ad.copy(line2 = it) })
        part(a.t("Code postal", "Postal Code"), ad.postalCode, { ad.copy(postalCode = it) }, InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_CHARACTERS)
        part(a.t("Ville", "City"), ad.city, { ad.copy(city = it) })
        part(a.t("Région", "Region"), ad.region, { ad.copy(region = it) })
        part(a.t("Pays", "Country"), ad.country, { ad.copy(country = it) })
        return col
    }

    private fun menu(r: Row, trailing: MutableList<View>): View {
        val options = runCatching { menuOptions(original.itemType, r.field.id) }.getOrDefault(emptyList())
        if (options.isEmpty()) return input(r.field.label, text(r.field.value)).also { e -> watch(e) { setValue(r, fromText(FfiFieldType.MENU, it)) } }
        val cur = text(r.field.value).ifEmpty { null }
        return picker(r, trailing, cur) {
            val labels = (listOf(a.t("Aucun", "None")) + options).toTypedArray()
            android.app.AlertDialog.Builder(a).setTitle(r.field.label)
                .setSingleChoiceItems(labels, cur?.let { options.indexOf(it) + 1 } ?: 0) { d, i ->
                    setValue(r, if (i == 0) FfiFieldValue.Empty else FfiFieldValue.Menu(options[i - 1]))
                    d.dismiss()
                    redraw()
                }.show()
        }
    }

    private fun itemLink(r: Row, trailing: MutableList<View>): View {
        val id = (r.field.value as? FfiFieldValue.ItemLink)?.itemId
        val linked = id?.let { x -> a.summaries.firstOrNull { it.id == x } }
        return picker(r, trailing, linked?.title?.ifBlank { a.t("Sans titre", "Untitled") } ?: id?.let { a.t("Élément introuvable", "Item not found") }) {
            val list = a.active.filter { it.id != original.id }.sortedBy { it.title.lowercase() }
            android.app.AlertDialog.Builder(a).setTitle(a.t("Choisir un élément", "Choose an Item"))
                .setItems(list.map { it.title.ifBlank { a.t("Sans titre", "Untitled") } }.toTypedArray()) { _, i ->
                    setValue(r, FfiFieldValue.ItemLink(list[i].id))
                    redraw()
                }.show()
        }
    }

    companion object {
        const val CUSTOM = "custom"
        private const val PREFIX = "custom_"
    }
}
