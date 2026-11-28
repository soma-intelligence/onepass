package me.somalabs.onepass.screens

import android.app.Dialog
import android.graphics.Typeface
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.text.DateFormat
import java.util.Date
import me.somalabs.onepass.MainActivity
import me.somalabs.onepass.R
import me.somalabs.onepass.core.FfiDevice
import me.somalabs.onepass.core.FfiDeviceKind
import me.somalabs.onepass.core.FfiDeviceMode
import me.somalabs.onepass.core.OnePassException
import me.somalabs.onepass.core.mailboxEnroll
import me.somalabs.onepass.core.mailboxGenerateCredential
import me.somalabs.onepass.ui.Ios
import me.somalabs.onepass.vault.LanPairing
import me.somalabs.onepass.vault.SyncManager
import me.somalabs.onepass.vaultkit.pairing.PairingFailure
import me.somalabs.onepass.vaultkit.pairing.PairingHostFlow
import me.somalabs.onepass.vaultkit.pairing.PairingJoinFlow
import me.somalabs.onepass.vaultkit.sync.MailboxHome
import me.somalabs.onepass.vaultkit.sync.SyncBackendState
import me.somalabs.onepass.vaultkit.sync.SyncChoice

/**
 * Appareils (spec 2b 4.3, iOS DevicesSettings): the signed device list,
 * rename, "Retirer cet appareil" for any other device after a confirmation
 * and the master password, the devices restored with the Emergency Kit that
 * ask to be trusted, and "Ajouter un appareil": this device shows a code (as
 * the Mac's "Configurer un appareil"), the new device types it, both compare
 * the 6-digit code, this one grants. The new device's side ("Ajouter cet
 * appareil" on the welcome screen) is [join].
 */
class PairingScreens(private val a: MainActivity) {
    private val ui get() = a.ui

    fun kindText(k: FfiDeviceKind) = when (k) {
        FfiDeviceKind.PHONE -> "iPhone"
        FfiDeviceKind.TABLET -> "iPad"
        FfiDeviceKind.MAC -> "Mac"
        FfiDeviceKind.VISION -> "Apple Vision Pro"
        FfiDeviceKind.OTHER -> a.t("Autre appareil", "Other device")
        FfiDeviceKind.ANDROID -> "Android"
        FfiDeviceKind.WINDOWS -> "Windows"
        FfiDeviceKind.LINUX -> "Linux"
    }

    fun modeText(m: FfiDeviceMode) = when (m) {
        FfiDeviceMode.PERSONAL -> a.t("Personnel", "Personal")
        FfiDeviceMode.SHARED -> a.t("Partagé", "Shared")
        FfiDeviceMode.PUBLIC -> "Public"
    }

    fun failureText(f: PairingFailure): String = when (f) {
        PairingFailure.BAD_CODE -> a.t("Ce code n'est pas valide. Vérifie-le : 8 caractères, par exemple K7QM-4XPR.", "This code is not valid. Check it: 8 characters, for example K7QM-4XPR.")
        PairingFailure.HOST_NOT_FOUND -> a.t("Rapproche les deux appareils et vérifie qu'ils sont sur le même Wi-Fi.", "Bring both devices closer and check they are on the same Wi-Fi.")
        PairingFailure.CONNECTION_LOST -> a.t("La connexion avec l'autre appareil a été coupée.", "The connection with the other device was lost.")
        PairingFailure.CANCELLED_BY_PEER -> a.t("L'autre appareil a annulé l'appairage.", "The other device cancelled the pairing.")
        PairingFailure.CODE_REJECTED -> a.t("Appairage annulé. Rien n'a été envoyé.", "Pairing cancelled. Nothing was sent.")
        PairingFailure.REFUSED -> a.t("L'appairage a été refusé. Recommence depuis le début.", "The pairing was refused. Start again from the beginning.")
        PairingFailure.PEER_TIMEOUT -> a.t("Le nouvel appareil n'a pas confirmé à temps. Recommence l'appairage.", "The new device did not confirm in time. Start the pairing again.")
        PairingFailure.GRANT_EXPIRED -> a.t("Le délai est dépassé. Le compte reçu a été effacé de cet appareil : recommence l'appairage.", "Time is up. The received account was erased from this device: start the pairing again.")
        PairingFailure.TOO_MANY_ATTEMPTS -> a.t("Trop d'essais. Le compte reçu a été effacé de cet appareil : recommence l'appairage.", "Too many attempts. The received account was erased from this device: start the pairing again.")
        PairingFailure.OTHER -> a.t("L'appairage n'a pas abouti", "Pairing didn't go through")
    }

    // ---- Appareils ---------------------------------------------------------------------

    fun devices(): View = a.pushedPage(a.t("Appareils", "Devices"), largeTitle = true) {
        val s = a.vault.session ?: return@pushedPage
        val list = runCatching { s.devices() }.getOrDefault(emptyList())
        val me = runCatching { s.thisDeviceId() }.getOrNull()
        fun isMe(d: FfiDevice) = d.isThisDevice || d.id == me
        val df = DateFormat.getDateInstance(DateFormat.MEDIUM)
        val active = list.filter { !it.revoked }.sortedWith(compareBy({ !isMe(it) }, { it.addedAt }))
        val revoked = list.filter { it.revoked }.sortedByDescending { it.revokedAt ?: 0 }
        val err = ui.footnote("", ui.red)
        addView(ui.capsLabel(a.t("Sur ton compte", "On your account")))
        addView(ui.inset(ui.card(*active.map { d ->
            lateinit var r: LinearLayout
            r = ui.row(icon = ui.symbolTile(R.drawable.ic_phone, ui.accent),
                title = d.name + if (isMe(d)) a.t(" · Cet appareil", " · This Device") else "",
                subtitle = a.t("${kindText(d.kind)} · ${modeText(d.mode)} · ajouté le ${df.format(Date(d.addedAt * 1000))}", "${kindText(d.kind)} · ${modeText(d.mode)} · added on ${df.format(Date(d.addedAt * 1000))}"),
                chevron = false, trailing = ui.glyph(R.drawable.ic_more_circle, ui.secondary, 24)) { deviceMenu(d, isMe(d), r, err) }
            r
        }.toTypedArray())))
        addView(ui.footnote(a.t("Liste signée par ton compte.", "List signed by your account.")))

        // Devices restored with the Emergency Kit ask this one to trust them (spec 7.5).
        val asking = runCatching { s.kitRestoredDevices() }.getOrDefault(emptyList())
        if (asking.isNotEmpty()) {
            addView(ui.capsLabel(a.t("Restaurés avec l'Emergency Kit", "Restored with the Emergency Kit")))
            addView(ui.inset(ui.card(*asking.map { k ->
                ui.row(title = k.name, subtitle = a.t("Demande ta confiance", "Asks for your trust"), chevron = false,
                    trailing = ui.text(a.t("Faire confiance", "Trust"), 17f, ui.readableAccent).apply { setPadding(ui.dp(8), 0, ui.dp(4), 0) }) {
                    a.confirm(a.t("Faire confiance à ${k.name} ?", "Trust ${k.name}?"), a.t("Faire confiance", "Trust"), destructive = false) {
                        a.background({
                            val keys = a.vault.deviceKeys()
                            try { s.acceptKitRestored(k.id, keys.classical, keys.pq) } finally { keys.wipe() }
                        }) { r -> r.onSuccess { a.sync.localChange(); a.render() }.onFailure { err.text = a.message(it) } }
                    }
                }
            }.toTypedArray())))
            addView(ui.footnote(a.t("Seulement si tu viens de restaurer ce compte avec ton Emergency Kit sur cet appareil.", "Only if you just restored this account with your Emergency Kit on that device.")))
        }

        addView(ui.inset(ui.card(ui.row(icon = ui.glyph(R.drawable.ic_add, ui.accent, 24).apply { layoutParams = LinearLayout.LayoutParams(ui.dp(30), ui.dp(24)) },
            title = a.t("Ajouter un appareil", "Add a Device"), titleColor = ui.readableAccent, chevron = false) { host() }), top = Ios.Space.XL))
        addView(ui.footnote(a.t("Cet appareil affiche un code à saisir sur le nouvel appareil (« Ajouter cet appareil »), puis vous comparez un code à 6 chiffres.",
            "This device shows a code to type on the new device (“Add This Device”), then you compare a 6-digit code.")))
        if (revoked.isNotEmpty()) {
            addView(ui.capsLabel(a.t("Retirés", "Removed")))
            addView(ui.inset(ui.card(*revoked.map { d ->
                ui.row(icon = ui.symbolTile(R.drawable.ic_phone, ui.tertiary), title = d.name,
                    subtitle = d.revokedAt?.let { a.t("${kindText(d.kind)} · Retiré le ${df.format(Date(it * 1000))}", "${kindText(d.kind)} · Removed on ${df.format(Date(it * 1000))}") } ?: kindText(d.kind), chevron = false)
            }.toTypedArray())))
        }
        addView(err)
    }

    private fun deviceMenu(d: FfiDevice, isMe: Boolean, anchor: View, err: TextView) {
        val entries = mutableListOf<Triple<Int, String, () -> Unit>>(Triple(R.drawable.ic_edit, a.t("Renommer", "Rename")) { rename(d, err) })
        if (!isMe) entries += Triple(R.drawable.ic_person_off, a.t("Retirer cet appareil", "Remove This Device")) { revoke(d, err) }
        a.menu(anchor, entries, destructive = setOf(a.t("Retirer cet appareil", "Remove This Device")))
    }

    private fun rename(d: FfiDevice, err: TextView) {
        val name = ui.field(a.t("Nom", "Name"), d.name)
        a.sheet(a.t("Renommer l'appareil", "Rename Device"), a.t("Annuler", "Cancel"), a.t("Renommer", "Rename") to { dlg: Dialog ->
            val n = name.text.toString().trim().take(64)
            dlg.dismiss()
            if (n.isEmpty() || n == d.name) return@to
            val s = a.session() ?: return@to
            a.background({ s.renameDevice(d.id, n) }) { r -> r.onSuccess { a.sync.localChange(); a.render() }.onFailure { err.text = a.message(it) } }
        }) { _ -> LinearLayout(a).apply { orientation = LinearLayout.VERTICAL; setPadding(0, ui.dp(8), 0, ui.dp(40)); addView(ui.inset(ui.card(name))) } }
    }

    /** "Retirer cet appareil": confirmation, the master password, then the revocation and the advice. */
    private fun revoke(d: FfiDevice, err: TextView) {
        android.app.AlertDialog.Builder(a)
            .setTitle(a.t("Retirer ${d.name} ?", "Remove ${d.name}?"))
            .setMessage(a.t("Il efface ses données Cleon dès qu'il voit la liste des appareils. Tu pourras l'ajouter de nouveau plus tard.",
                "It erases its Cleon data as soon as it sees the device list. You can add it again later."))
            .setPositiveButton(a.t("Retirer cet appareil", "Remove This Device")) { _, _ ->
                passwordSheet(a.t("Retirer ${d.name}", "Remove ${d.name}"), a.t("Confirme avec ton mot de passe maître pour retirer cet appareil.", "Confirm with your master password to remove this device.")) { done ->
                    val s = a.session() ?: return@passwordSheet
                    a.background({ s.revokeDevice(d.id) }) { r ->
                        done(r.exceptionOrNull())
                        r.onSuccess {
                            a.sync.localChange()
                            a.render()
                            android.app.AlertDialog.Builder(a)
                                .setTitle(a.t("${d.name} est retiré", "${d.name} is removed"))
                                .setMessage(a.t("Change ton mot de passe maître si cet appareil a été perdu ou volé.", "Change your master password if this device was lost or stolen."))
                                .setPositiveButton(a.t("Plus tard", "Later"), null)
                                .show()
                        }.onFailure { err.text = a.message(it) }
                    }
                }
            }
            .setNegativeButton(a.t("Annuler", "Cancel"), null)
            .show()
            .getButton(android.app.AlertDialog.BUTTON_POSITIVE).setTextColor(ui.red)
    }

    /** The master password, checked, then `then` (its callback closes the sheet or shows the error). */
    private fun passwordSheet(title: String, footer: String, then: (done: (Throwable?) -> Unit) -> Unit) {
        val pw = ui.field(a.t("Mot de passe maître", "Master Password"), password = true)
        val err = ui.footnote("", ui.red)
        a.sheet(title, a.t("Annuler", "Cancel"), a.t("Confirmer", "Confirm") to { d: Dialog ->
            val chars = pw.text.toString().toCharArray()
            if (chars.isEmpty()) return@to
            pw.text.clear()
            a.background({ a.vault.accountUnlockKey(chars).fill(0) }) { r ->
                chars.fill(' ')
                r.onSuccess { then { e -> if (e == null) d.dismiss() else err.text = a.message(e) } }
                    .onFailure { err.text = if (it is OnePassException.WrongPassword) a.t("Mot de passe incorrect.", "Incorrect password.") else a.message(it) }
            }
        }) { _ ->
            LinearLayout(a).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(0, ui.dp(8), 0, ui.dp(40))
                addView(ui.inset(ui.card(pw)))
                addView(ui.footnote(footer))
                addView(err)
            }
        }
        pw.requestFocus()
    }

    // ---- Ajouter un appareil (this device shows the code) ---------------------------------

    private fun host() {
        val coordinator = a.sync.coordinator
        if (coordinator == null) {
            a.toast(a.t("Active d'abord la synchronisation : Réglages > Sync.", "Turn on sync first: Settings > Sync."))
            return
        }
        val box = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL; setPadding(0, ui.dp(8), 0, ui.dp(40)) }
        lateinit var dialog: Dialog
        lateinit var flow: PairingHostFlow
        val pw = ui.field(a.t("Mot de passe maître", "Master Password"), password = true)
        val err = ui.footnote("", ui.red)
        var approving = false
        fun draw(st: PairingHostFlow.State) {
            box.removeAllViews()
            when (st) {
                PairingHostFlow.State.Connecting -> box.addView(status(a.t("Préparation...", "Preparing..."), null))
                is PairingHostFlow.State.Hosting -> {
                    box.addView(ui.text(a.t("Sur le nouvel appareil", "On the new device"), 22f, ui.label, 700).apply { gravity = Gravity.CENTER; setPadding(ui.dp(16), ui.dp(16), ui.dp(16), ui.dp(6)) })
                    box.addView(ui.text(a.t("Choisis « Ajouter cet appareil », puis saisis ce code.", "Choose “Add This Device”, then type this code."), 15f, ui.secondary).apply { gravity = Gravity.CENTER; setPadding(ui.dp(24), 0, ui.dp(24), ui.dp(24)) })
                    box.addView(ui.text(st.code.shortText, 40f, ui.label, 600).apply {
                        typeface = Typeface.create(Typeface.MONOSPACE, 600, false)
                        letterSpacing = 0.1f
                        gravity = Gravity.CENTER
                        contentDescription = a.t("Code d'appairage", "Pairing code") + " " + st.code.shortText.filter { it != '-' }.toList().joinToString(" ")
                    })
                    box.addView(ui.footnote(a.t("Un nouveau code s'affiche toutes les 30 s.", "A new code shows every 30 s.")).apply { gravity = Gravity.CENTER })
                    box.addView(ui.footnote(a.t("Ne montre ce code qu'à ton propre appareil, devant toi.", "Show this code only to your own device, in front of you.")).apply { gravity = Gravity.CENTER })
                    box.addView(ui.footnote(a.t("Les deux appareils doivent être proches, sur le même Wi-Fi.", "Both devices must be close, on the same Wi-Fi.")).apply { gravity = Gravity.CENTER })
                }
                is PairingHostFlow.State.Comparing -> {
                    box.addView(ui.inset(ui.card(ui.row(icon = ui.symbolTile(R.drawable.ic_phone, ui.accent, 40), title = st.peer.name,
                        subtitle = a.t("${kindText(st.peer.kind)} · demande un accès ${modeText(st.mode)}", "${kindText(st.peer.kind)} · asks for ${modeText(st.mode)} access"), chevron = false, minHeightDp = 64))))
                    box.addView(ui.footnote(a.t("Il recevra tout ton compte et ta Secret Key, puis te demandera ton mot de passe maître.", "It will receive your whole account and your Secret Key, then ask for your master password.")))
                    box.addView(ui.capsLabel(a.t("Code de vérification", "Verification code")))
                    box.addView(sas(st.sas))
                    box.addView(ui.footnote(a.t("Le même code doit s'afficher sur le nouvel appareil. S'il est différent, quelqu'un d'autre essaie de se connecter.", "The same code must appear on the new device. If it differs, someone else is trying to connect.")))
                    box.addView(ui.inset(ui.card(pw.detached()), top = Ios.Space.L))
                    box.addView(ui.footnote(a.t("Confirme avec ton mot de passe maître.", "Confirm with your master password.")))
                    box.addView(err.detached())
                    if (st.mode != FfiDeviceMode.PERSONAL) {
                        err.text = a.t("Sur Android, seul un appareil personnel s'ajoute pour l'instant.", "On Android, only a personal device can be added for now.")
                    }
                    box.addView(ui.inset(ui.card(
                        ui.row(title = a.t("Les codes sont identiques", "The codes match"), titleColor = ui.readableAccent, chevron = false) {
                            if (approving || st.mode != FfiDeviceMode.PERSONAL) return@row
                            val chars = pw.text.toString().toCharArray()
                            if (chars.isEmpty()) { err.text = a.t("Confirme avec ton mot de passe maître.", "Confirm with your master password."); return@row }
                            approving = true
                            pw.text.clear()
                            err.text = ""
                            a.background({
                                try { a.vault.accountUnlockKey(chars).fill(0) } finally { chars.fill(' ') }
                            }) { r ->
                                r.onFailure {
                                    approving = false
                                    err.text = if (it is OnePassException.WrongPassword) a.t("Mot de passe incorrect.", "Incorrect password.") else a.message(it)
                                }.onSuccess { approve(flow) }
                            }
                        },
                        ui.row(title = a.t("Ils sont différents", "They're different"), titleColor = ui.red, chevron = false) { flow.cancel() },
                    ), top = Ios.Space.L))
                }
                PairingHostFlow.State.WaitingForPeer -> box.addView(status(a.t("En attente du nouvel appareil...", "Waiting for the new device..."), a.t("Confirme que les codes sont identiques sur le nouvel appareil.", "Confirm the codes match on the new device.")))
                PairingHostFlow.State.Granting -> box.addView(status(a.t("Envoi...", "Sending..."), null))
                PairingHostFlow.State.WaitingForAck -> box.addView(status(a.t("Envoi...", "Sending..."), a.t("Il te demande maintenant ton mot de passe maître.", "It now asks for your master password.")))
                is PairingHostFlow.State.Done -> {
                    box.addView(outcome(R.drawable.ic_check_circle, ui.green, a.t("Appareil ajouté", "Device added"), a.t("Il te demande maintenant ton mot de passe maître.", "It now asks for your master password.")))
                }
                is PairingHostFlow.State.Failed -> box.addView(outcome(R.drawable.ic_info, ui.red, a.t("L'appairage n'a pas abouti", "Pairing didn't go through"), failureText(st.failure)))
            }
        }
        val listener = me.somalabs.onepass.vaultkit.pairing.CompositeListener(listOf(LanPairing.listener(a), me.somalabs.onepass.vaultkit.pairing.RendezvousPairingListener(coordinator.home.endpoint)))
        flow = PairingHostFlow(listener, { st -> a.main.post { if (dialog.isShowing) draw(st) } })
        dialog = a.sheet(a.t("Ajouter un appareil", "Add a Device"), a.t("Fermer", "Close"), null) { _ -> box }
        dialog.setOnDismissListener {
            flow.cancel()
            a.render()
        }
        draw(PairingHostFlow.State.Connecting)
        flow.start()
    }

    /** The grant, off the main thread: a sync round first (the server's view is sealed), then the device list goes out. */
    private fun approve(flow: PairingHostFlow) {
        val sync = a.sync
        val s = a.vault.session ?: return
        Thread {
            flow.approve(
                seal = { ap ->
                    val c = sync.coordinator ?: throw IllegalStateException("no sync")
                    c.syncNow()
                    val key = a.vault.secretKey()
                    ap.sealFullGrant(s, key, FfiDeviceMode.PERSONAL, false, c.client)
                },
                introduce = { ap ->
                    val keys = a.vault.deviceKeys()
                    try { ap.introduce(s, keys.classical, keys.pq) } finally { keys.wipe() }
                    sync.localChange()
                    sync.coordinator?.syncNow()
                },
            )
        }.apply { isDaemon = true; start() }
    }

    private fun sas(code: String) = ui.text(code.chunked(3).joinToString(" "), 40f, ui.label, 600).apply {
        typeface = Typeface.create(Typeface.MONOSPACE, 600, false)
        gravity = Gravity.CENTER
        setPadding(0, ui.dp(8), 0, ui.dp(8))
        contentDescription = code.toList().joinToString(" ")
    }

    private fun status(title: String, detail: String?) = LinearLayout(a).apply {
        orientation = LinearLayout.VERTICAL
        gravity = Gravity.CENTER_HORIZONTAL
        setPadding(ui.dp(24), ui.dp(48), ui.dp(24), ui.dp(24))
        addView(android.widget.ProgressBar(a))
        addView(ui.text(title, 17f, ui.label, 600).apply { gravity = Gravity.CENTER; setPadding(0, ui.dp(14), 0, 0) })
        detail?.let { addView(ui.text(it, 15f, ui.secondary).apply { gravity = Gravity.CENTER; setPadding(0, ui.dp(6), 0, 0) }) }
    }

    private fun outcome(icon: Int, color: Int, title: String, message: String) = LinearLayout(a).apply {
        orientation = LinearLayout.VERTICAL
        gravity = Gravity.CENTER_HORIZONTAL
        setPadding(ui.dp(24), ui.dp(40), ui.dp(24), ui.dp(24))
        addView(ui.glyph(icon, color, 56))
        addView(ui.text(title, 22f, ui.label, 700).apply { gravity = Gravity.CENTER; setPadding(0, ui.dp(14), 0, ui.dp(6)) })
        addView(ui.text(message, 15f, ui.secondary).apply { gravity = Gravity.CENTER })
    }

    // ---- Ajouter cet appareil (the new device types the code) --------------------------------

    /**
     * The new device's side, from the welcome screen: the code typed, the
     * 6-digit comparison, the wait for the approval, the master password;
     * then the mailbox of the grant is joined with this device's credential
     * and the account opens here.
     */
    fun join(back: () -> Unit) {
        val vault = a.vault
        val device = vault.newDevice()
        val credential = runCatching { mailboxGenerateCredential() }.getOrNull()
        val root = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL; setPadding(ui.dp(28), ui.dp(40), ui.dp(28), ui.dp(40)) }
        val page = ScrollView(a).apply { isFillViewport = true; setBackgroundColor(ui.page); addView(root) }
        var flow: PairingJoinFlow? = null
        val code = a.syncScreens.codeField("K7QM-4XPR")
        val pw = ui.field(a.t("Mot de passe maître", "Master Password"), password = true)
        val err = ui.text("", 14f, ui.red).apply { setPadding(ui.dp(4), ui.dp(8), ui.dp(4), 0) }
        var busy = false
        // A self-hosted server with its own CA: the mailbox of the grant is joined through it.
        var server: SyncChoice = SyncChoice.Hosted
        fun full(v: View, top: Int = 0) = root.addView(v, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = ui.dp(top) })
        fun title(t: String, sub: String?) {
            root.addView(ui.text(t, 28f, ui.label, 700))
            sub?.let { root.addView(ui.text(it, 16f, ui.secondary).apply { setPadding(0, ui.dp(8), 0, 0) }) }
        }
        fun leave() {
            flow?.cancel()
            device.wipe()
            credential?.seed?.fill(0)
            back()
        }
        fun draw(st: PairingJoinFlow.State?) {
            root.removeAllViews()
            when (st) {
                null -> {
                    title(a.t("Saisis le code", "Type the code"), a.t("Sur ton autre appareil : Réglages > Appareils > Ajouter un appareil (sur Mac : Configurer un appareil). Le code à 8 caractères s'affiche.",
                        "On your other device: Settings > Devices > Add a Device (on a Mac: Set Up a Device). The 8-character code shows."))
                    full(ui.card(code.detached()), 24)
                    full(ui.text(a.t("Les deux appareils doivent être proches, sur le même Wi-Fi.", "Both devices must be close, on the same Wi-Fi."), 13f, ui.secondary).apply { setPadding(ui.dp(4), ui.dp(8), 0, 0) })
                    val serverRow = ui.row(title = a.t("Serveur", "Server"), value = a.syncScreens.choiceName(server))
                    serverRow.setOnClickListener { a.syncScreens.choiceSheet(server, allowLocal = false) { c -> server = c; draw(null) } }
                    full(ui.card(serverRow), 16)
                    full(ui.text(a.t("À changer seulement si ton serveur a sa propre autorité de certification.", "Change it only if your server has its own certificate authority."), 13f, ui.secondary).apply { setPadding(ui.dp(4), ui.dp(8), 0, 0) })
                    full(err.detached())
                    full(ui.capsule(a.t("Rejoindre", "Join")) {
                        val text = code.text.toString().trim()
                        if (text.isEmpty()) return@capsule
                        if (credential == null) { err.text = a.t("L'appairage n'a pas abouti", "Pairing didn't go through"); return@capsule }
                        val endpoint = (server as? SyncChoice.SelfHost)?.let { me.somalabs.onepass.core.FfiMailboxEndpoint(it.url, it.extraCaPem) }
                            ?: me.somalabs.onepass.core.FfiMailboxEndpoint(me.somalabs.onepass.vaultkit.sync.MailboxEndpoints.HOSTED, null)
                        // The local network (iPhone, Mac) and the server's rendezvous (Windows, Android elsewhere).
                        val f = PairingJoinFlow(listOf(LanPairing.connector(a), me.somalabs.onepass.vaultkit.pairing.RendezvousPairingConnector(endpoint)),
                            SyncManager.deviceName(), FfiDeviceKind.ANDROID, device.keys, credential.publicKey,
                            { st -> a.main.post { if (page.isAttachedToWindow && st !is PairingJoinFlow.State.Importing) draw(st) } })
                        flow = f
                        f.join(text)
                        draw(PairingJoinFlow.State.Joining)
                    }, 24)
                }
                PairingJoinFlow.State.Joining -> root.addView(status(a.t("Connexion à ton autre appareil...", "Connecting to your other device..."), null))
                is PairingJoinFlow.State.Comparing -> {
                    title(a.t("Code de vérification", "Verification code"), a.t("Le même code doit s'afficher sur ton autre appareil.", "The same code must show on your other device."))
                    full(sas(st.sas), 24)
                    full(ui.capsule(a.t("Les codes sont identiques", "The codes match")) { flow?.confirmCode() }, 24)
                    full(ui.capsule(a.t("Ils sont différents", "They're different"), prominent = false, color = ui.red) { flow?.cancel() }, 12)
                }
                PairingJoinFlow.State.WaitingForApproval -> root.addView(status(a.t("En attente de ton autre appareil...", "Waiting for your other device..."), a.t("Confirme sur ton autre appareil que les codes sont identiques.", "Confirm on your other device that the codes match.")))
                is PairingJoinFlow.State.ReceivedFull, PairingJoinFlow.State.Importing -> {
                    title(a.t("Ton mot de passe maître", "Your master password"), a.t("Ton compte est arrivé. Saisis ton mot de passe maître pour l'ouvrir sur cet appareil.", "Your account arrived. Enter your master password to open it on this device."))
                    full(ui.card(pw.detached()), 24)
                    full(err.detached())
                    val go = ui.capsule(a.t("Déverrouiller", "Unlock")) {
                        val f = flow ?: return@capsule
                        val received = f.state as? PairingJoinFlow.State.ReceivedFull ?: return@capsule
                        val p = pw.text.toString()
                        if (p.isEmpty() || busy) return@capsule
                        busy = true
                        err.setTextColor(ui.secondary)
                        err.text = a.t("Déverrouillage...", "Unlocking...")
                        a.background({
                            // The mailbox of the grant first: nothing is imported if it cannot be joined.
                            val enrollment = received.enrollment
                            val home = enrollment?.let {
                                val endpointCa = (server as? SyncChoice.SelfHost)?.extraCaPem
                                val joined = mailboxEnroll(credential!!.seed, it.ticket, endpointCa)
                                MailboxHome(joined.baseUrl, joined.mailboxId, endpointCa)
                            }
                            val (unlocked, secretKey) = f.importAndUnlock(vault.dbPath, p)
                            unlocked.auk.fill(0)
                            vault.adopt(unlocked.session, secretKey, device)
                            home?.let { a.sync.joined(it, credential!!.seed) }
                        }) { r ->
                            busy = false
                            err.setTextColor(ui.red)
                            r.onSuccess {
                                device.wipe()
                                credential?.seed?.fill(0)
                                pw.text.clear()
                                a.openTabs()
                            }.onFailure {
                                err.text = when (it) {
                                    is OnePassException.WrongPassword -> a.t("Mot de passe incorrect.", "Incorrect password.") + " " + a.t("Tu peux réessayer.", "You can try again.")
                                    is OnePassException.MailboxUnavailable -> a.t("Impossible de joindre le serveur. Vérifie ta connexion puis réessaie.", "Can't reach the server. Check your connection and try again.")
                                    else -> a.message(it)
                                }
                            }
                        }
                    }
                    full(go, 24)
                }
                PairingJoinFlow.State.Done -> root.addView(status(a.t("Ouverture...", "Opening..."), null))
                is PairingJoinFlow.State.Failed -> {
                    root.addView(outcome(R.drawable.ic_info, ui.red, a.t("L'appairage n'a pas abouti", "Pairing didn't go through"), failureText(st.failure)))
                    full(ui.capsule(a.t("Recommencer", "Start Again")) { leave(); a.showFull { a.pairing.joinPage(back) } }, 24)
                }
            }
            if (st !is PairingJoinFlow.State.Failed && st !is PairingJoinFlow.State.Done) full(a.link(a.t("Annuler", "Cancel")) { leave() }.apply { gravity = Gravity.CENTER }, 8)
        }
        draw(null)
        joinView = page
    }

    private var joinView: View? = null

    /** The page of [join], for `showFull`. */
    fun joinPage(back: () -> Unit): View {
        join(back)
        return joinView!!
    }
}

/** The view, out of its previous parent (a page redrawn with the same fields). */
private fun <V : View> V.detached(): V = apply { (parent as? ViewGroup)?.removeView(this) }
