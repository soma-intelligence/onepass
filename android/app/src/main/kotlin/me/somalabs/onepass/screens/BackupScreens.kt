package me.somalabs.onepass.screens

import android.app.Activity
import android.app.Dialog
import android.content.Intent
import android.net.Uri
import android.provider.OpenableColumns
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import java.text.DateFormat
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import me.somalabs.onepass.MainActivity
import me.somalabs.onepass.R
import me.somalabs.onepass.core.FfiArchiveInfo
import me.somalabs.onepass.core.FfiArchiveKind
import me.somalabs.onepass.core.FfiImportChoice
import me.somalabs.onepass.core.FfiImportDecision
import me.somalabs.onepass.core.FfiImportSummary
import me.somalabs.onepass.core.FfiRestoreSummary
import me.somalabs.onepass.core.OnePassException
import me.somalabs.onepass.core.detectImportFormat
import me.somalabs.onepass.core.importFormats
import me.somalabs.onepass.core.inspectArchive
import me.somalabs.onepass.ui.Category
import me.somalabs.onepass.ui.Ios

/**
 * Réglages > Général, "Importer…" and "Sauvegarde" as on iPhone
 * (GeneralSettings, ImportSheet, BackupSheets): an encrypted backup
 * (master password, then a passphrase), restoring one (nothing in OnePass is
 * overwritten), the unencrypted CSV export for leaving, and importing the
 * export of another manager with its possible duplicates.
 *
 * Files only go through the system's document picker (SAF); the bytes and
 * passphrases are wiped when done.
 */
class BackupScreens(private val a: MainActivity) {
    private val ui get() = a.ui

    /** The two sections of Général. */
    fun sections(col: LinearLayout) {
        col.addView(ui.inset(ui.card(
            ui.row(icon = ui.symbolTile(R.drawable.ic_import, ui.blue), title = a.t("Importer…", "Import…")) { importer() },
        ), top = Ios.Space.XL))
        col.addView(ui.footnote(a.t("Apple, 1Password, Bitwarden, navigateurs et 8 autres.", "Apple, 1Password, Bitwarden, browsers and 8 more.")))
        col.addView(ui.sectionHeader(a.t("Sauvegarde", "Backup")))
        col.addView(ui.inset(ui.card(
            ui.row(icon = ui.symbolTile(R.drawable.ic_lock, ui.accent), title = a.t("Sauvegarde chiffrée…", "Encrypted Backup…")) { export() },
            ui.row(icon = ui.symbolTile(R.drawable.ic_restore, ui.green), title = a.t("Restaurer…", "Restore…")) { restore() },
            ui.row(icon = ui.symbolTile(R.drawable.ic_breached, ui.orange), title = a.t("Export CSV non chiffré…", "Unencrypted CSV Export…")) { plaintext() },
        )))
        col.addView(ui.footnote(a.t("Restaurer n'écrase rien. Le CSV sert seulement à changer de gestionnaire.", "Restoring overwrites nothing. Use the CSV only to switch managers.")))
    }

    private fun sheetBody(build: LinearLayout.() -> Unit): LinearLayout = LinearLayout(a).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(0, ui.dp(8), 0, ui.dp(40))
        build()
    }

    private fun secret(hint: String) = ui.field(hint, password = true).apply { typeface = android.graphics.Typeface.DEFAULT }

    /** Writes [bytes] where the user picks (SAF), then wipes them. */
    private fun saveAs(name: String, mime: String, bytes: ByteArray, done: () -> Unit) {
        val i = Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType(mime).putExtra(Intent.EXTRA_TITLE, name)
        a.launch(i) { code, data ->
            val uri = data?.data
            if (code != Activity.RESULT_OK || uri == null) { bytes.fill(0); return@launch }
            a.background({
                try { a.contentResolver.openOutputStream(uri, "wt")?.use { it.write(bytes) } ?: throw java.io.IOException() } finally { bytes.fill(0) }
            }) { r ->
                r.onSuccess { done() }.onFailure { a.toast(a.t("Le fichier n'a pas pu être enregistré.", "The file could not be saved.")) }
            }
        }
    }

    /** Reads a file the user picks (50 MB at most), with its name. */
    private fun open(mime: String = "*/*", then: (name: String, bytes: ByteArray) -> Unit) {
        val i = Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType(mime)
        a.launch(i) { code, data ->
            val uri: Uri = data?.data ?: return@launch
            if (code != Activity.RESULT_OK) return@launch
            a.background({
                var name = "export"
                a.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c -> if (c.moveToFirst()) c.getString(0)?.let { name = it } }
                val bytes = a.contentResolver.openInputStream(uri)?.use { input ->
                    val out = java.io.ByteArrayOutputStream()
                    val buf = ByteArray(64 * 1024)
                    var total = 0L
                    while (true) {
                        val n = input.read(buf); if (n < 0) break
                        total += n; if (total > 50L * 1024 * 1024) throw java.io.IOException("too large")
                        out.write(buf, 0, n)
                    }
                    out.toByteArray()
                } ?: throw java.io.IOException()
                name to bytes
            }) { r ->
                r.onSuccess { then(it.first, it.second) }.onFailure { a.toast(a.t("Ce fichier n'a pas pu être lu, ou il est trop gros.", "This file could not be read, or it is too large.")) }
            }
        }
    }

    private fun day() = SimpleDateFormat("yyyy-MM-dd", Locale.ROOT).format(Date())

    // ---- encrypted backup ------------------------------------------------------------------------

    private fun export() {
        val pw = secret(a.t("Mot de passe maître", "Master Password"))
        val p1 = secret(a.t("Phrase de passe de la sauvegarde", "Backup Passphrase"))
        val p2 = secret(a.t("Confirmer la phrase de passe", "Confirm the passphrase"))
        val err = ui.footnote("", ui.red)
        a.sheet(a.t("Sauvegarde chiffrée", "Encrypted Backup"), a.t("Annuler", "Cancel"), a.t("Exporter", "Export") to { d: Dialog ->
            val phrase = p1.text.toString()
            when {
                pw.text.isEmpty() || phrase.isEmpty() -> return@to
                phrase != p2.text.toString() -> { err.text = a.t("Les deux phrases de passe ne correspondent pas.", "The two passphrases don't match."); return@to }
            }
            val chars = pw.text.toString().toCharArray()
            val bytes = phrase.toByteArray()
            pw.text.clear(); p1.text.clear(); p2.text.clear()
            err.text = ""
            val s = a.session() ?: return@to
            a.background({
                a.vault.accountUnlockKey(chars).fill(0)
                s.exportEncryptedBackup(bytes)
            }) { r ->
                chars.fill(' '); bytes.fill(0)
                r.onSuccess { archive ->
                    d.dismiss()
                    a.confirm(a.t("Le fichier contient tout ton coffre, chiffré avec la phrase de passe que tu viens de choisir. Range-le hors ligne, par exemple sur une clé USB : les clouds et les messageries en gardent une copie ailleurs.",
                        "The file holds your whole vault, encrypted with the passphrase you just chose. Keep it offline, on a USB drive for example: clouds and messaging apps keep a copy elsewhere."), a.t("Continuer", "Continue"), destructive = false) {
                        saveAs(a.t("OnePass sauvegarde ${day()}.onepass", "OnePass backup ${day()}.onepass"), "application/octet-stream", archive) {
                            a.toast(a.t("Sauvegarde enregistrée", "Backup saved"))
                        }
                    }
                }.onFailure {
                    err.text = when (it) {
                        is OnePassException.WrongPassword -> a.t("Mot de passe incorrect.", "Incorrect password.")
                        is OnePassException.Validation, is OnePassException.InvalidInput -> a.t("Choisis une phrase longue que tu n'utilises nulle part ailleurs, par exemple plusieurs mots. OnePass refuse une phrase trop facile à deviner.",
                            "Choose a long passphrase you don't use anywhere else, several words for example. OnePass refuses one that is too easy to guess.")
                        else -> a.message(it)
                    }
                }
            }
        }) { _ ->
            sheetBody {
                addView(ui.footnote(a.t("Une archive OnePass chiffrée de tout ce que cet appareil contient, coffres et éléments à la corbeille compris. Elle s'ouvre avec la phrase de passe choisie ici ou avec ton compte.",
                    "An encrypted OnePass archive of everything on this device, vaults and deleted items included. It opens with the passphrase chosen here or with your account.")))
                addView(ui.inset(ui.card(pw), top = Ios.Space.S))
                addView(ui.inset(ui.card(p1, p2), top = Ios.Space.L))
                addView(ui.footnote(a.t("Choisis une phrase longue que tu n'utilises nulle part ailleurs, par exemple plusieurs mots. OnePass refuse une phrase trop facile à deviner.",
                    "Choose a long passphrase you don't use anywhere else, several words for example. OnePass refuses one that is too easy to guess.")))
                addView(ui.footnote(a.t("Garde aussi ta phrase de passe : sans elle ni ton compte, la sauvegarde ne s'ouvre pas.", "Keep your passphrase too: without it or your account, the backup won't open.")))
                addView(err)
            }
        }
        pw.requestFocus()
    }

    // ---- restore ---------------------------------------------------------------------------------

    private fun restore() {
        open { _, bytes ->
            val info = runCatching { a.session()?.archiveInfo(bytes) ?: inspectArchive(bytes) }.getOrElse {
                bytes.fill(0)
                return@open a.toast(a.t("Ce fichier n'a pas pu être lu, ou il est trop gros.", "This file could not be read, or it is too large."))
            }
            restoreSheet(bytes, info)
        }
    }

    private fun restoreSheet(bytes: ByteArray, info: FfiArchiveInfo) {
        val s = a.session() ?: return
        var phrase: ByteArray? = null
        var preview: FfiRestoreSummary? = null
        lateinit var body: LinearLayout
        lateinit var dialog: Dialog
        val pass = secret(a.t("Phrase de passe de la sauvegarde", "Backup Passphrase"))
        val err = ui.footnote("", ui.red)
        fun counts(r: FfiRestoreSummary) = r.byType.joinToString("\n") { "${Category.of(it.itemType).plural(a)} : ${it.count}" }
        fun draw() {
            body.removeAllViews()
            val df = DateFormat.getDateTimeInstance(DateFormat.LONG, DateFormat.SHORT)
            body.addView(ui.inset(ui.card(
                ui.row(title = if (info.kind == FfiArchiveKind.BACKUP) a.t("Sauvegarde du compte", "Account backup") else a.t("Export OnePass", "OnePass export"),
                    subtitle = df.format(Date(info.createdAt * 1000)), chevron = false),
                ui.row(title = when {
                    info.forThisAccount -> a.t("Signée par ton compte : la signature est vérifiée à l'ouverture", "Signed by your account: the signature is checked when it opens")
                    info.signed -> a.t("Signée par un autre compte : seule la phrase de passe protège ce fichier", "Signed by another account: only the passphrase protects this file")
                    else -> a.t("Non signée : seule la phrase de passe protège ce fichier", "Not signed: only the passphrase protects this file")
                }, chevron = false),
            ), top = Ios.Space.S))
            val p = preview
            if (p == null) {
                if (!info.forThisAccount) {
                    body.addView(ui.footnote(a.t("Cette sauvegarde n'est pas pour ce compte : elle s'ouvre avec la phrase de passe choisie à l'export.", "This backup is not for this account: it opens with the passphrase chosen when it was exported.")))
                    body.addView(ui.inset(ui.card(pass), top = Ios.Space.S))
                }
            } else {
                val rows = mutableListOf<View>()
                if (p.items == 0u) rows += ui.row(title = a.t("Tout ce que contient cette sauvegarde est déjà dans OnePass.", "Everything in this backup is already in OnePass."), chevron = false)
                if (p.vaultsCreated > 0u) rows += ui.row(title = if (p.vaultsCreated == 1u) a.t("1 coffre sera créé", "1 vault will be created") else a.t("${p.vaultsCreated} coffres seront créés", "${p.vaultsCreated} vaults will be created"), chevron = false)
                if (p.skipped > 0u) rows += ui.row(title = if (p.skipped == 1u) a.t("1 élément déjà présent, laissé tel quel", "1 item already here, left as it is") else a.t("${p.skipped} éléments déjà présents, laissés tels quels", "${p.skipped} items already here, left as they are"), chevron = false)
                if (p.items > 0u) rows += ui.row(title = a.t("Contenu", "Contents"), subtitle = null, chevron = false).apply {
                    addView(ui.text(counts(p), 15f, ui.secondary).apply { gravity = Gravity.END })
                }
                body.addView(ui.inset(ui.card(*rows.toTypedArray()), top = Ios.Space.L))
                body.addView(ui.footnote(a.t("Les éléments gardent leur identifiant, ceux de la corbeille et les archivés compris.", "Items keep their identifier, deleted and archived ones included.")))
            }
            body.addView(err)
        }
        fun previewNow() {
            err.text = ""
            val ph = if (info.forThisAccount) null else pass.text.toString().toByteArray().also { pass.text.clear() }
            if (!info.forThisAccount && ph!!.isEmpty()) return
            a.background({ s.previewRestore(bytes, ph) }) { r ->
                r.onSuccess { phrase = ph; preview = it; draw() }.onFailure {
                    ph?.fill(0)
                    err.text = if (it is OnePassException.WrongPassword || it is OnePassException.Crypto) a.t("Phrase de passe incorrecte.", "Incorrect passphrase.") else a.message(it)
                }
            }
        }
        dialog = a.sheet(a.t("Restaurer une sauvegarde", "Restore a Backup"), a.t("Annuler", "Cancel"), a.t("Restaurer", "Restore") to { d: Dialog ->
            val p = preview
            if (p == null) return@to previewNow()
            if (p.items == 0u) return@to d.dismiss()
            a.background({ s.restoreArchive(bytes, phrase) }) { r ->
                r.onSuccess { done ->
                    d.dismiss()
                    a.toast(if (done.items == 1u) a.t("1 élément restauré", "1 item restored") else a.t("${done.items} éléments restaurés", "${done.items} items restored"))
                    a.changed()
                }.onFailure { err.text = a.message(it) }
            }
        }) { _ -> sheetBody { body = this; draw() } }
        dialog.setOnDismissListener { bytes.fill(0); phrase?.fill(0) }
        if (info.forThisAccount) previewNow()
    }

    // ---- unencrypted CSV ---------------------------------------------------------------------------

    private fun plaintext() {
        val pw = secret(a.t("Mot de passe maître", "Master Password"))
        val err = ui.footnote("", ui.red)
        var understood = false
        val chosen = a.vaults.map { it.id }.toMutableSet()
        a.sheet(a.t("Export non chiffré", "Unencrypted Export"), a.t("Annuler", "Cancel"), a.t("Exporter", "Export") to { d: Dialog ->
            if (!understood || chosen.isEmpty() || pw.text.isEmpty()) return@to
            val chars = pw.text.toString().toCharArray()
            pw.text.clear()
            val s = a.session() ?: return@to
            a.background({ a.vault.accountUnlockKey(chars).fill(0); s.exportPlaintextCsv(chosen.toList()) }) { r ->
                chars.fill(' ')
                r.onSuccess { csv ->
                    d.dismiss()
                    a.confirm(a.t("Ce fichier n'est pas chiffré. Choisis un emplacement hors ligne et supprime-le après usage.", "This file is not encrypted. Choose an offline location and delete it after use."),
                        a.t("Enregistrer le fichier…", "Save File…")) {
                        saveAs("OnePass export ${day()}.csv", "text/csv", csv) { a.toast(a.t("Export enregistré", "Export saved")) }
                    }
                }.onFailure { err.text = if (it is OnePassException.WrongPassword) a.t("Mot de passe incorrect.", "Incorrect password.") else a.message(it) }
            }
        }) { _ ->
            sheetBody {
                addView(ui.inset(ui.card(LinearLayout(a).apply {
                    gravity = Gravity.CENTER_VERTICAL
                    setPadding(ui.dp(16), ui.dp(14), ui.dp(16), ui.dp(14))
                    addView(ui.glyph(R.drawable.ic_breached, ui.orange, 28).apply { (layoutParams as LinearLayout.LayoutParams).marginEnd = ui.dp(12) })
                    addView(ui.text(a.t("Ce fichier n'est pas chiffré. Toute personne ou app qui y accède lit tous tes mots de passe, codes et notes. Un tableur peut exécuter une cellule qui commence par « = ». Les passkeys et les lieux n'y figurent pas.",
                        "This file is not encrypted. Anyone or any app that reaches it reads all your passwords, codes and notes. A spreadsheet can run a cell that starts with “=”. Passkeys and places are not in it."), 15f, ui.label),
                        LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
                }), top = Ios.Space.S))
                addView(ui.footnote(a.t("Pour une copie de sécurité, préfère la sauvegarde chiffrée. N'utilise ce fichier que pour passer à un autre gestionnaire, puis supprime-le.",
                    "For a safety copy, use the encrypted backup. Use this file only to move to another manager, then delete it.")))
                addView(ui.inset(ui.card(ui.toggleRow(a.t("Je comprends que ce fichier n'est pas chiffré", "I understand this file is not encrypted"), on = false) { understood = it }), top = Ios.Space.S))
                addView(ui.capsLabel(a.t("Coffres", "Vaults")))
                addView(ui.inset(ui.card(*a.vaults.map { v -> ui.toggleRow(v.meta.name, on = true) { on -> if (on) chosen.add(v.id) else chosen.remove(v.id) } }.toTypedArray())))
                addView(ui.footnote(a.t("Les éléments de la corbeille ne sont pas exportés.", "Items in Recently Deleted are not exported.")))
                addView(ui.inset(ui.card(pw), top = Ios.Space.L))
                addView(ui.footnote(a.t("Supprime le fichier dès que tu n'en as plus besoin, corbeille comprise.", "Delete the file as soon as you no longer need it, and empty the Trash.")))
                addView(err)
            }
        }
    }

    // ---- import from another manager ---------------------------------------------------------------

    private fun formatName(f: String) = when (f) {
        "safari-csv" -> a.t("Mots de passe Apple (Safari, CSV)", "Apple Passwords (Safari, CSV)")
        "chrome-csv" -> a.t("Chrome et navigateurs Chromium", "Chrome and Chromium browsers")
        "1pux" -> "1Password (1PUX)"
        "1password-csv" -> "1Password (CSV)"
        "dashlane-csv" -> "Dashlane (CSV)"
        "dashlane-zip" -> "Dashlane (ZIP)"
        "protonpass-csv" -> "Proton Pass (CSV)"
        "nordpass-csv" -> "NordPass (CSV)"
        "keeper-csv" -> "Keeper (CSV)"
        "enpass-json" -> "Enpass (JSON)"
        "roboform-csv" -> "RoboForm (CSV)"
        "cxf" -> a.t("Autre gestionnaire (Credential Exchange)", "Other manager (Credential Exchange)")
        "pdf-text" -> a.t("Identifiants en PDF", "Credentials PDF")
        "bitwarden-json" -> "Bitwarden (JSON)"
        "bitwarden-csv" -> "Bitwarden (CSV)"
        "firefox-csv" -> "Firefox (CSV)"
        "lastpass-csv" -> "LastPass (CSV)"
        "keepass-xml" -> "KeePass (XML)"
        "otpauth" -> a.t("Codes à usage unique", "One-Time Codes")
        "wifi-qr" -> a.t("Réseaux Wi-Fi (QR)", "Wi-Fi Networks (QR)")
        "onepass-csv" -> a.t("Export CSV OnePass", "OnePass CSV export")
        else -> f
    }

    private fun importer() {
        a.sheet(a.t("Importer", "Import"), a.t("Annuler", "Cancel"), null) { d ->
            sheetBody {
                addView(ui.footnote(a.t("Choisis l'export de ton ancien gestionnaire (CSV, JSON, 1PUX, XML…). OnePass reconnaît le format au contenu.",
                    "Choose your old manager's export (CSV, JSON, 1PUX, XML…). OnePass recognizes the format from its content.")))
                addView(ui.inset(ui.card(ui.row(icon = ui.glyph(R.drawable.ic_import, ui.accent, 24), title = a.t("Choisir le fichier", "Choose File"), titleColor = ui.readableAccent, chevron = false) {
                    open { name, bytes ->
                        val f = runCatching { detectImportFormat(name, bytes) }.getOrNull()
                        when {
                            f == "onepass" -> { d.dismiss(); restoreSheet(bytes, runCatching { a.session()?.archiveInfo(bytes) ?: inspectArchive(bytes) }.getOrElse { bytes.fill(0); return@open a.toast(a.message(it)) }) }
                            f != null -> { d.dismiss(); importPreview(name, bytes, f) }
                            else -> {
                                val formats = runCatching { importFormats() }.getOrDefault(emptyList())
                                android.app.AlertDialog.Builder(a).setTitle(a.t("Format non reconnu. Choisis la source de l'export dans la liste.", "Unrecognized format. Choose where the export came from in the list."))
                                    .setItems(formats.map(::formatName).toTypedArray()) { _, i -> d.dismiss(); importPreview(name, bytes, formats[i]) }
                                    .setNegativeButton(a.t("Annuler", "Cancel")) { _, _ -> bytes.fill(0) }.show()
                            }
                        }
                    }
                }), top = Ios.Space.S))
                addView(ui.footnote(a.t("Le fichier est lu sur cet appareil, jamais envoyé ni gardé. Supprime l'export une fois l'import fait : il contient tes mots de passe en clair.",
                    "The file is read on this device, never sent or kept. Delete the export once imported: it holds your passwords in clear text.")))
            }
        }
    }

    private fun importPreview(name: String, bytes: ByteArray, format: String) {
        val s = a.session() ?: return
        var vault = a.vaults.firstOrNull() ?: return
        var summary: FfiImportSummary? = null
        val choices = mutableMapOf<UInt, FfiImportChoice>()
        lateinit var body: LinearLayout
        val err = ui.footnote("", ui.red)
        var reload: () -> Unit = {}
        fun choiceLabel(c: FfiImportChoice) = when (c) {
            FfiImportChoice.MERGE -> a.t("Fusionner", "Merge")
            FfiImportChoice.SKIP -> a.t("Ignorer", "Skip")
            FfiImportChoice.IMPORT -> a.t("Importer", "Import")
        }
        fun draw() {
            body.removeAllViews()
            body.addView(ui.inset(ui.card(
                ui.row(title = name, subtitle = formatName(format), chevron = false),
                ui.row(title = a.t("Coffre", "Vault"), value = vault.meta.name, chevron = a.vaults.size > 1, onClick = if (a.vaults.size > 1) ({
                    android.app.AlertDialog.Builder(a).setItems(a.vaults.map { it.meta.name }.toTypedArray()) { _, i -> vault = a.vaults[i]; summary = null; reload() }.show()
                }) else null),
            ), top = Ios.Space.S))
            val p = summary ?: run { body.addView(ui.footnote(a.t("Lecture du fichier…", "Reading File…"))); body.addView(err); return }
            if (p.items == 0u) body.addView(ui.footnote(a.t("Aucun élément à importer dans ce fichier.", "There's nothing to import in this file.")))
            else {
                body.addView(ui.capsLabel(a.t("Contenu", "Contents")))
                body.addView(ui.inset(ui.card(*p.byType.map { tc -> ui.row(icon = a.itemIcon(tc.itemType, 30), title = Category.of(tc.itemType).plural(a), value = "${tc.count}", chevron = false) }.toTypedArray())))
                val notes = mutableListOf<String>()
                if (p.updated > 0u) notes += a.t("${p.updated} mis à jour depuis un import précédent", "${p.updated} updated from an earlier import")
                if (p.unchanged > 0u) notes += a.t("${p.unchanged} déjà à jour", "${p.unchanged} already up to date")
                if (p.skipped > 0u) notes += a.t("${p.skipped} sans rien de nouveau, laissés de côté", "${p.skipped} with nothing new, left out")
                val warned = p.warnings.sumOf { it.count.toInt() }
                if (warned > 0) notes += a.t("$warned éléments importés avec une remarque", "$warned items imported with a note")
                if (notes.isNotEmpty()) body.addView(ui.footnote(notes.joinToString(" · ")))
            }
            if (p.duplicates.isNotEmpty()) {
                body.addView(ui.sectionHeader(a.t("Doublons possibles", "Possible Duplicates")))
                body.addView(ui.footnote(a.t("Ces éléments du fichier ressemblent à des éléments déjà dans ce coffre. Les copies exactes sont ignorées et les autres fusionnées, sauf si tu choisis autrement.",
                    "These items of the file look like items already in this vault. Exact copies are skipped and the others merged, unless you choose otherwise.")))
                body.addView(ui.inset(ui.card(*p.duplicates.map { dup ->
                    val c = choices[dup.index] ?: dup.suggested
                    ui.row(icon = a.itemIcon(dup.incoming.itemType, 30), title = dup.incoming.title.ifBlank { a.t("Sans titre", "Untitled") },
                        subtitle = (if (dup.exact) a.t("Copie exacte · ", "Exact copy · ") else "") + a.t("Dans le coffre : ", "In the vault: ") + dup.existing.title,
                        value = choiceLabel(c), chevron = false) {
                        val all = listOf(FfiImportChoice.MERGE, FfiImportChoice.SKIP, FfiImportChoice.IMPORT)
                        android.app.AlertDialog.Builder(a).setTitle(a.t("Choix", "Choice")).setSingleChoiceItems(all.map(::choiceLabel).toTypedArray(), all.indexOf(c)) { dd, i ->
                            choices[dup.index] = all[i]; dd.dismiss(); draw()
                        }.show()
                    }
                }.toTypedArray())))
            }
            body.addView(ui.footnote(a.t("Le fichier est lu sur cet appareil, jamais envoyé ni gardé.", "The file is read on this device, never sent or kept.")))
            body.addView(err)
        }
        fun load() {
            draw()
            a.background({ s.previewImportInto(format, bytes, vault.id) }) { r ->
                r.onSuccess { summary = it; draw() }.onFailure { err.text = if (it is OnePassException.InvalidInput) a.t("Ce fichier n'a pas pu être lu : ", "This file could not be read: ") + it.message.orEmpty() else a.message(it); draw() }
            }
        }
        reload = { load() }
        val dialog = a.sheet(a.t("Importer", "Import"), a.t("Annuler", "Cancel"), a.t("Importer", "Import") to { d: Dialog ->
            val p = summary ?: return@to
            if (p.items == 0u) return@to d.dismiss()
            val decisions = choices.map { (i, c) -> FfiImportDecision(i, c) }
            err.text = a.t("Import en cours…", "Importing…")
            a.background({ s.importItems(format, bytes, vault.id, decisions) }) { r ->
                r.onSuccess { done ->
                    d.dismiss()
                    a.toast(if (done.items == 1u) a.t("1 élément importé dans « ${vault.meta.name} »", "1 item imported into “${vault.meta.name}”")
                    else a.t("${done.items} éléments importés dans « ${vault.meta.name} »", "${done.items} items imported into “${vault.meta.name}”"))
                    a.changed()
                }.onFailure { err.text = a.message(it) }
            }
        }) { _ -> sheetBody { body = this } }
        dialog.setOnDismissListener { bytes.fill(0) }
        load()
    }

}
