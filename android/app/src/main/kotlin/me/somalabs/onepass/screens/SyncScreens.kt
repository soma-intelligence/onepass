package me.somalabs.onepass.screens

import android.app.Dialog
import android.content.Intent
import android.graphics.Typeface
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import me.somalabs.onepass.MainActivity
import me.somalabs.onepass.R
import me.somalabs.onepass.core.FfiMailboxEndpoint
import me.somalabs.onepass.ui.Ios
import me.somalabs.onepass.vaultkit.sync.MailboxEndpoints
import me.somalabs.onepass.vaultkit.sync.MailboxSetupOutcome
import me.somalabs.onepass.vaultkit.sync.SyncBackendState
import me.somalabs.onepass.vaultkit.sync.SyncChoice
import me.somalabs.onepass.vaultkit.sync.SyncStatus

/**
 * Réglages > Sync, as on iPhone (SyncSettings, mailbox path): where the
 * account syncs, the status line, "Synchroniser maintenant". Android has no
 * iCloud: an account kept on this device turns sync on here, which creates
 * its mailbox as a new account's setup does. And "Où est rangé mon coffre ?"
 * (SyncChoiceSheet): the Cleon server, the user's own server (https URL,
 * optional CA in PEM, pasted or picked from a file, "Tester"), or this
 * device only.
 */
class SyncScreens(private val a: MainActivity) {
    private val ui get() = a.ui
    private val sync get() = a.sync

    fun open() = a.push { page() }

    /** The status line of the settings page, as iOS words it. Null color: secondary. */
    fun statusText(s: SyncStatus): Pair<String, Int> = when (s) {
        SyncStatus.Disabled -> a.t("Synchronisation désactivée", "Sync off") to ui.secondary
        SyncStatus.Offline -> a.t("Hors ligne", "Offline") to ui.orange
        SyncStatus.Syncing -> a.t("Synchronisation en cours", "Syncing") to ui.label
        SyncStatus.Retrying -> a.t("La synchronisation reprendra dans un instant", "Sync will resume in a moment") to ui.red
        SyncStatus.ClockSkew -> a.t("Vérifie l'heure de l'appareil", "Check the device's time") to ui.red
        SyncStatus.Unreadable -> a.t("Un enregistrement du serveur est illisible", "A record from the server can't be read") to ui.red
        SyncStatus.WaitingForMailbox -> a.t("Synchronisation en attente du serveur", "Sync waiting for the server") to ui.secondary
        is SyncStatus.HomeMoved -> a.t("Ton coffre a changé de serveur", "Your vault moved to another server") to ui.red
        is SyncStatus.Refused -> a.t("Données refusées", "Data refused") + " · " + s.kind to ui.red
        is SyncStatus.Idle -> (s.lastSync?.let { ago(it) } ?: a.t("En attente de la première synchronisation", "Waiting for First Sync")) to ui.label
    }

    /** "Synchronisé à l'instant", "Synchronisé il y a 3 minutes". */
    private fun ago(at: Long): String {
        val s = (System.currentTimeMillis() - at) / 1000
        if (s < 45) return a.t("Synchronisé à l'instant", "Synced Just Now")
        val m = (s + 30) / 60
        val rel = when {
            m < 60 -> if (m <= 1) a.t("il y a 1 minute", "1 minute ago") else a.t("il y a $m minutes", "$m minutes ago")
            m < 60 * 24 -> (m / 60).let { h -> if (h == 1L) a.t("il y a 1 heure", "1 hour ago") else a.t("il y a $h heures", "$h hours ago") }
            else -> (m / 1440).let { d -> if (d == 1L) a.t("hier", "yesterday") else a.t("il y a $d jours", "$d days ago") }
        }
        return a.t("Synchronisé ", "Synced ") + rel
    }

    fun page(): View = a.pushedPage("Sync", largeTitle = true) {
        val backend = sync.backend
        val hosted = sync.hostedName()
        val here = a.t("Cet appareil", "This device")
        val statusView = ui.text("", 17f)
        val statusRow = LinearLayout(a).apply {
            gravity = Gravity.CENTER_VERTICAL
            minimumHeight = ui.dp(52)
            setPadding(ui.dp(16), ui.dp(10), ui.dp(16), ui.dp(10))
            addView(statusView, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        }
        var syncing = false
        lateinit var syncNow: LinearLayout
        fun drawStatus(s: SyncStatus) {
            val (text, color) = statusText(if (backend is SyncBackendState.PendingSetup && s == SyncStatus.Disabled) SyncStatus.Offline else s)
            statusView.text = if (backend is SyncBackendState.PendingSetup) a.t("Configuration en attente", "Setup pending") else text
            statusView.setTextColor(if (backend is SyncBackendState.PendingSetup) ui.orange else color)
            val enabled = sync.coordinator != null && !syncing && s != SyncStatus.Syncing && s !is SyncStatus.HomeMoved
            syncNow.isEnabled = enabled
            syncNow.alpha = if (enabled) 1f else 0.45f
        }
        syncNow = ui.row(title = a.t("Synchroniser maintenant", "Sync Now"), titleColor = ui.readableAccent, chevron = false) {
            if (syncing) return@row
            syncing = true
            drawStatus(SyncStatus.Syncing)
            sync.syncNow { syncing = false; drawStatus(sync.status) }
        }
        syncNow.contentDescription = a.t("Synchroniser maintenant", "Sync Now")
        val rows = mutableListOf<View>()
        if (backend !is SyncBackendState.Local) rows += ui.row(title = a.t("Synchronisé avec", "Synced With"), value = backend.displayName(hosted, here), chevron = false)
        rows += statusRow
        rows += syncNow
        addView(ui.inset(ui.card(*rows.toTypedArray()), top = Ios.Space.S))
        drawStatus(sync.status)
        val listener: (SyncStatus) -> Unit = { s -> if (statusView.isAttachedToWindow) drawStatus(s) }
        sync.onStatus(listener)
        statusView.addOnAttachStateChangeListener(object : View.OnAttachStateChangeListener {
            override fun onViewAttachedToWindow(v: View) {}
            override fun onViewDetachedFromWindow(v: View) = sync.removeStatus(listener)
        })
        // "Synchronisé il y a 1 minute" moves on.
        a.tick(object : Runnable {
            override fun run() {
                if (!statusView.isAttachedToWindow) return
                if (!syncing) drawStatus(sync.status)
                a.main.postDelayed(this, 30_000)
            }
        })

        when (backend) {
            is SyncBackendState.Mailbox -> addView(ui.footnote(when (sync.status) {
                is SyncStatus.Refused -> a.t("Rien de ce que le serveur a envoyé n'a été utilisé.", "Nothing the server sent was used.")
                SyncStatus.WaitingForMailbox -> a.t("Le serveur a une version plus ancienne. Cleon renvoie la sienne, rien à faire.", "The server has an older version. Cleon sends its own back, nothing to do.")
                else -> a.t("Chiffré avant de quitter l'appareil.", "Encrypted before it leaves the device.")
            }))
            is SyncBackendState.PendingSetup -> pending(this, backend)
            SyncBackendState.Local -> local(this)
        }
    }

    /** A setup that could not finish: why, "Réessayer", and "Annuler" while the server has nothing. */
    private fun pending(col: LinearLayout, backend: SyncBackendState.PendingSetup) = with(col) {
        val why = when (val e = sync.setupError) {
            is MailboxSetupOutcome.Failed -> setupMessage(e)
            else -> a.t("Impossible de joindre le serveur. Vérifie ta connexion puis réessaie.", "Can't reach the server. Check your connection and try again.")
        }
        addView(ui.footnote(why + " " + a.t("Ton coffre reste sur cet appareil ; la configuration reprend à chaque déverrouillage.", "Your vault stays on this device; the setup resumes at each unlock.")))
        val err = ui.footnote("", ui.red)
        val retry = ui.row(title = a.t("Réessayer", "Try Again"), titleColor = ui.readableAccent, chevron = false)
        retry.setOnClickListener {
            retry.isEnabled = false
            err.text = a.t("Configuration...", "Setting up...")
            sync.enable(backend.choice) { outcome -> err.text = ""; retry.isEnabled = true; after(outcome) }
        }
        val cancel = ui.row(title = a.t("Garder le coffre sur cet appareil", "Keep the Vault on This Device"), titleColor = ui.red, chevron = false) {
            sync.cancelPendingSetup { ok ->
                if (ok) a.render() else err.text = a.t("Le serveur a déjà créé la boîte de ce compte : la configuration doit se terminer.", "The server already created this account's mailbox: the setup has to finish.")
            }
        }
        addView(ui.inset(ui.card(retry, cancel), top = Ios.Space.L))
        addView(err)
    }

    /** An account on this device only: the server to use, then "Activer la synchronisation". */
    private fun local(col: LinearLayout) = with(col) {
        addView(ui.footnote(a.t("Ton coffre reste sur cet appareil. Active la synchronisation pour le retrouver sur tes autres appareils et le restaurer avec ton Emergency Kit.",
            "Your vault stays on this device. Turn on sync to get it on your other devices and to restore it with your Emergency Kit.")))
        var choice: SyncChoice = SyncChoice.Hosted
        val server = ui.row(title = a.t("Serveur", "Server"), value = choiceName(choice))
        server.setOnClickListener {
            choiceSheet(choice, allowLocal = false) { c ->
                choice = c
                ((server.getChildAt(1)) as? TextView)?.text = choiceName(c)
            }
        }
        val err = ui.footnote("", ui.red)
        val go = ui.row(title = a.t("Activer la synchronisation", "Turn On Sync"), titleColor = ui.readableAccent, chevron = false)
        go.setOnClickListener {
            go.isEnabled = false
            err.setTextColor(ui.secondary)
            err.text = a.t("Configuration...", "Setting up...")
            sync.enable(choice) { outcome ->
                go.isEnabled = true
                err.setTextColor(ui.red)
                err.text = ""
                after(outcome)
            }
        }
        addView(ui.inset(ui.card(server, go), top = Ios.Space.L))
        addView(err)
    }

    private fun after(outcome: MailboxSetupOutcome) {
        when (outcome) {
            is MailboxSetupOutcome.Ready -> a.toast(a.t("Ton coffre se synchronise maintenant avec ", "Your vault now syncs with ") + sync.serverName(outcome.home.baseUrl))
            is MailboxSetupOutcome.Offline -> a.toast(a.t("Impossible de joindre le serveur. Vérifie ta connexion puis réessaie.", "Can't reach the server. Check your connection and try again."))
            is MailboxSetupOutcome.Failed -> a.toast(setupMessage(outcome))
            MailboxSetupOutcome.Local -> Unit
        }
        a.render()
    }

    fun setupMessage(f: MailboxSetupOutcome.Failed): String = when {
        f.error.message == me.somalabs.onepass.vaultkit.sync.MailboxSetup.BAD_URL ->
            a.t("Cette adresse de serveur n'est pas valide. Elle doit commencer par https://.", "This server address isn't valid. It must start with https://.")
        f.error is me.somalabs.onepass.core.OnePassException.Forbidden ->
            a.t("Le serveur de synchronisation refuse cette action à cet appareil.", "The sync server doesn't allow this device to do that.")
        f.error is me.somalabs.onepass.core.OnePassException.ClockSkew -> a.t("Vérifie l'heure de l'appareil", "Check the device's time")
        else -> a.message(f.error)
    }

    fun choiceName(c: SyncChoice): String = when (c) {
        SyncChoice.Hosted -> sync.hostedName()
        is SyncChoice.SelfHost -> MailboxEndpoints.displayName(c.url, sync.hostedName())
        SyncChoice.Local -> a.t("Cet appareil seulement", "This Device Only")
    }

    // ---- Où est rangé mon coffre ? ---------------------------------------------------------

    /**
     * "Où est rangé mon coffre ?" (SyncChoiceSheet): the Cleon server
     * (default), the user's own server with a "Tester" button, or, on
     * Android, this device only (`allowLocal`).
     */
    fun choiceSheet(current: SyncChoice, allowLocal: Boolean, onSave: (SyncChoice) -> Unit) {
        var option = current
        val url = ui.field(a.t("URL de base (https://...)", "Base URL (https://...)"), (current as? SyncChoice.SelfHost)?.url ?: "").apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        }
        val ca = ui.field(a.t("Autorité de certification en PEM (facultatif)", "Certificate authority in PEM (optional)"), (current as? SyncChoice.SelfHost)?.extraCaPem ?: "").apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            isSingleLine = false
            minLines = 3
            maxLines = 6
            textSize = 13f
            typeface = Typeface.MONOSPACE
        }
        val result = ui.footnote("")
        val selfBox = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL }
        val rowsBox = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL }
        fun typedUrl(): String? = url.text.toString().trim().takeIf { MailboxEndpoints.validate(it) }
        fun draw() {
            rowsBox.removeAllViews()
            fun row(o: SyncChoice, title: String, detail: String?) = ui.row(title = title, subtitle = null, chevron = false,
                trailing = if (o::class == option::class) ui.glyph(R.drawable.ic_check, ui.accent, 22) else null) { option = if (o is SyncChoice.SelfHost && option is SyncChoice.SelfHost) option else o; draw() }.apply {
                detail?.let { d -> ((getChildAt(0) as LinearLayout)).addView(ui.text(d, 13f, ui.secondary).apply { setPadding(0, ui.dp(3), 0, 0) }) }
            }
            val rows = mutableListOf<View>(
                row(SyncChoice.Hosted, sync.hostedName(), a.t("Hébergé par Soma Labs, chiffré sur ton appareil avant l'envoi", "Hosted by Soma Labs, encrypted on your device before it's sent")),
                row(SyncChoice.SelfHost("", null), a.t("Mon serveur", "My Server"), null),
            )
            if (allowLocal) rows += row(SyncChoice.Local, a.t("Cet appareil seulement", "This Device Only"),
                a.t("Rien ne quitte cet appareil. Tu pourras activer la synchronisation plus tard dans Réglages > Sync.", "Nothing leaves this device. You can turn on sync later in Settings > Sync."))
            rowsBox.addView(ui.inset(ui.card(*rows.toTypedArray()), top = Ios.Space.S))
            selfBox.visibility = if (option is SyncChoice.SelfHost) View.VISIBLE else View.GONE
        }
        selfBox.addView(ui.inset(ui.card(url, ca,
            ui.row(title = a.t("Choisir un fichier PEM", "Choose a PEM File"), titleColor = ui.readableAccent, chevron = false) {
                val i = Intent(Intent.ACTION_OPEN_DOCUMENT).apply { addCategory(Intent.CATEGORY_OPENABLE); type = "*/*" }
                a.launch(i) { code, data ->
                    val uri = data?.data ?: return@launch
                    if (code != android.app.Activity.RESULT_OK) return@launch
                    val text = runCatching { a.contentResolver.openInputStream(uri)?.use { it.readBytes().take(64 * 1024).toByteArray() } }.getOrNull()
                    val pem = text?.let { String(it, Charsets.US_ASCII) }
                    if (pem != null && pem.contains("-----BEGIN CERTIFICATE-----")) ca.setText(pem.trim())
                    else result.text = a.t("Ce fichier n'est pas un certificat PEM.", "This file isn't a PEM certificate.")
                }
            },
            ui.row(title = a.t("Tester", "Test"), titleColor = ui.readableAccent, chevron = false) {
                val u = typedUrl() ?: run { result.text = a.t("L'adresse doit commencer par https://.", "The address must start with https://."); return@row }
                result.text = a.t("Test...", "Testing...")
                val endpoint = FfiMailboxEndpoint(u, MailboxEndpoints.pem(ca.text.toString()))
                a.background({ sync.check(endpoint) }) { r ->
                    result.text = if (r.getOrNull()?.isSuccess == true) a.t("Le serveur répond.", "The server answers.")
                    else a.t("Le serveur ne répond pas. Vérifie l'adresse.", "The server doesn't answer. Check the address.")
                }
            },
        ), top = Ios.Space.L))
        selfBox.addView(result)
        // Debug builds only (the CA is a debug asset, absent from release): the test mailbox of the
        // PC, reached through `adb reverse tcp:47800 tcp:47800`.
        val testCa = if (a.debuggable) runCatching { a.assets.open("test-mailbox-ca.pem").use { String(it.readBytes(), Charsets.US_ASCII) } }.getOrNull() else null
        if (testCa != null) selfBox.addView(ui.inset(ui.card(ui.row(title = a.t("Serveur de test (adb reverse, port 47800)", "Test Server (adb reverse, port 47800)"),
            titleColor = ui.readableAccent, chevron = false) {
            url.setText(TEST_URL)
            ca.setText(testCa.trim())
        }), top = Ios.Space.L))
        if (a.debuggable) selfBox.addView(ui.footnote(a.t("Build de test : un serveur de test joint par « adb reverse » s'utilise avec https://localhost:PORT/functions/v1/mailbox et son autorité de certification.",
            "Test build: a test server reached through “adb reverse” is used with https://localhost:PORT/functions/v1/mailbox and its certificate authority.")))
        draw()
        a.sheet(a.t("Où est rangé mon coffre ?", "Where Is My Vault Kept?"), a.t("Annuler", "Cancel"), a.t("Terminé", "Done") to { d: Dialog ->
            val chosen = when (option) {
                is SyncChoice.SelfHost -> {
                    val u = typedUrl() ?: run { result.setTextColor(ui.red); result.text = a.t("L'adresse doit commencer par https://.", "The address must start with https://."); return@to }
                    SyncChoice.SelfHost(u, MailboxEndpoints.pem(ca.text.toString()))
                }
                else -> option
            }
            d.dismiss()
            onSave(chosen)
        }) { _ ->
            LinearLayout(a).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(0, ui.dp(8), 0, ui.dp(40))
                addView(rowsBox)
                addView(selfBox)
            }
        }
    }

    companion object {
        /** The PC's test mailbox (desktop `test-mailbox`, default port) through `adb reverse`. */
        const val TEST_URL = "https://localhost:47800/functions/v1/mailbox"
    }

    /** A labeled monospace input for codes and keys (no suggestions, no learning). */
    fun codeField(hint: String): EditText = ui.field(hint).apply {
        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD or InputType.TYPE_TEXT_FLAG_CAP_CHARACTERS
        typeface = Typeface.MONOSPACE
    }
}
