package me.somalabs.onepass.screens

import android.app.AlertDialog
import android.app.Dialog
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.LinearLayout
import java.text.DateFormat
import java.util.Date
import java.util.Locale
import me.somalabs.onepass.MainActivity
import me.somalabs.onepass.R
import me.somalabs.onepass.core.FfiAdoptionProof
import me.somalabs.onepass.core.FfiContact
import me.somalabs.onepass.core.FfiContactLevel
import me.somalabs.onepass.core.FfiContactState
import me.somalabs.onepass.core.FfiIdentityChange
import me.somalabs.onepass.core.FfiItem
import me.somalabs.onepass.core.FfiMember
import me.somalabs.onepass.core.FfiRole
import me.somalabs.onepass.core.FfiZoneKind
import me.somalabs.onepass.core.OnePassException
import me.somalabs.onepass.ui.Ios
import me.somalabs.onepass.vaultkit.sharing.ContactInviteExpired
import me.somalabs.onepass.vaultkit.sharing.ContactInviteFlow
import me.somalabs.onepass.vaultkit.sharing.ContactZoneOffline

/**
 * Contacts and shared vaults as on iPhone (`App/Sharing`): Réglages >
 * Contacts (the book, "Non vérifié" on a contact added by link, the safety
 * number), the invitation by link both ways, the vault invitations, the
 * received items and the changed keys, the members of a shared vault with
 * their roles, "Partager ce coffre", "Retirer" and "Envoyer à un contact".
 * Names come from the contact book only; roles and rights from the core.
 */
class SharingScreens(private val a: MainActivity) {
    private val ui get() = a.ui
    private val sharing get() = a.sharing
    private val snap get() = sharing.snapshot

    private fun now() = System.currentTimeMillis() / 1000

    fun roleTitle(r: FfiRole) = when (r) {
        FfiRole.READ -> a.t("Lecture", "Read")
        FfiRole.WRITE -> a.t("Écriture", "Write")
        FfiRole.MANAGE -> a.t("Gestion", "Manage")
    }

    /** "Non vérifié" next to a contact added by link (spec 5.3.2). */
    fun unverifiedBadge(): View = ui.text(a.t("Non vérifié", "Not verified"), 12f, ui.orange, 600).apply {
        background = ui.rounded(Color.argb(0x24, Color.red(ui.orange), Color.green(ui.orange), Color.blue(ui.orange)), 10)
        setPadding(ui.dp(7), ui.dp(2), ui.dp(7), ui.dp(2))
    }

    private fun verifiedBadge(): View = ui.text(a.t("Vérifié", "Verified"), 13f, ui.green, 600)

    private fun avatar(name: String) = ui.monogram(name.take(1).uppercase().ifEmpty { "?" }, Color.rgb(0x8E, 0x8E, 0x93), 32)

    /** Runs `work` off the main thread, then reads the sharing state again and redraws; errors in `err` or a toast. */
    fun act(err: android.widget.TextView? = null, work: () -> Unit, done: () -> Unit = {}) {
        err?.text = ""
        a.background({
            work()
            a.vault.session?.let { sharing.readNow(it) }
        }) { r ->
            r.onSuccess {
                a.sync.localChange()
                done()
                a.reload { a.render() }
            }.onFailure { e -> err?.let { it.text = message(e) } ?: a.toast(message(e)) }
        }
    }

    /** The sharing errors in the iPhone's words; the rest as the app says them. */
    fun message(e: Throwable): String = when (e) {
        is OnePassException.ContactNotVerified -> a.t("Vérifie d'abord ce contact en personne ou avec son numéro de sécurité.", "Verify this contact in person or with their safety number first.")
        is OnePassException.IdentityPending -> a.t("Un gestionnaire du coffre doit confirmer tes nouvelles clés avant que tu puisses modifier.", "A vault manager must confirm your new keys before you can make changes.")
        is OnePassException.MembershipFork -> a.t("Le serveur a montré deux listes de membres différentes.", "The server showed two different member lists.")
        is OnePassException.ReadOnlyRole -> a.t("Tu peux seulement consulter ce coffre.", "You can only view this vault.")
        is OnePassException.Validation -> if (e.field == "zone") a.t("Le coffre partagé n'est pas encore prêt sur le serveur. Connecte-toi à Internet et réessaie.", "The shared vault is not ready on the server yet. Connect to the internet and try again.")
        else a.message(e)
        is ContactInviteExpired -> a.t("L'invitation a expiré. Envoie un nouveau lien.", "The invitation expired. Send a new link.")
        is ContactZoneOffline, is OnePassException.MailboxUnavailable -> a.t("Connecte-toi à Internet pour terminer l'ajout de ce contact.", "Connect to the internet to finish adding this contact.")
        is OnePassException.InvalidInput -> a.t("Ce lien d'invitation n'est pas valide.", "This invitation link is not valid.")
        else -> a.message(e)
    }

    private fun errorLine() = ui.footnote("", ui.red)

    // ---- Réglages > Contacts -----------------------------------------------------------------

    fun contacts() = a.push { contactsPage() }

    fun contactsPage(): View = a.pushedPage(a.t("Contacts", "Contacts"), largeTitle = true) {
        val contacts = snap.contacts.filter { it.state !is FfiContactState.Removed }.sortedBy { it.nameLocal.lowercase() }
        if (contacts.isEmpty()) addView(ui.footnote(a.t("Aucun contact. Ajoute quelqu'un en personne ou par lien.", "No contacts. Add someone in person or by link.")))
        else addView(ui.inset(ui.card(*contacts.map { c ->
            ui.row(icon = avatar(c.nameLocal), title = c.nameLocal,
                subtitle = if (c.state is FfiContactState.KeysChanged) a.t("Ses clés ont changé", "Their keys changed") else null,
                trailing = if (c.level == FfiContactLevel.LINK) unverifiedBadge() else null) { a.push { contactDetail(c.accountId) } }
        }.toTypedArray()), top = Ios.Space.S))

        addView(ui.sectionHeader(a.t("Ajouter un contact", "Add a contact")))
        val inviting = sharing.inviter?.state
        addView(ui.inset(ui.card(
            ui.row(icon = ui.glyph(R.drawable.ic_link, ui.accent, 24), title = a.t("Ajouter par lien", "Add by link"),
                subtitle = when (inviting) {
                    is ContactInviteFlow.State.Sharing -> a.t("En attente de la réponse…", "Waiting for a reply…")
                    else -> null
                }) { inviteByLink() },
            ui.row(icon = ui.glyph(R.drawable.ic_person_add, ui.accent, 24), title = a.t("Ouvrir un lien d'invitation", "Open an invitation link")) { openLink(null) },
        )))
        addView(ui.footnote(a.t("La vérification en personne avec le QR n'est pas encore sur Android : ajoute par lien, puis comparez le numéro de sécurité.",
            "In-person verification with the QR code is not on Android yet: add by link, then compare the safety number.")))

        // Waiting for an answer.
        val waiting = mutableListOf<View>()
        if (snap.shareInvites.isNotEmpty()) waiting += ui.row(title = a.t("Invitations", "Invitations"), value = "${snap.shareInvites.size}") { a.push { invitesPage() } }
        if (snap.receivedItems.isNotEmpty()) waiting += ui.row(title = a.t("Éléments reçus", "Received items"), value = "${snap.receivedItems.size}") { a.push { receivedPage() } }
        if (snap.identityChanges.isNotEmpty()) waiting += ui.row(title = a.t("Clés changées", "Changed keys"), value = "${snap.identityChanges.size}") { a.push { identityPage() } }
        if (waiting.isNotEmpty()) addView(ui.inset(ui.card(*waiting.toTypedArray()), top = Ios.Space.XL))
    }

    private fun contactDetail(accountId: String): View {
        val c = snap.contact(accountId)
        return a.pushedPage(a.t("Contacts", "Contacts")) {
            if (c == null) return@pushedPage
            val head = LinearLayout(a).apply {
                gravity = Gravity.CENTER_VERTICAL
                setPadding(ui.dp(16), ui.dp(14), ui.dp(16), ui.dp(14))
                addView(ui.text(c.nameLocal, 20f, ui.label, 600), LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
                addView(if (c.level == FfiContactLevel.LINK) unverifiedBadge() else verifiedBadge())
            }
            addView(ui.inset(ui.card(head), top = Ios.Space.S))
            if (c.level == FfiContactLevel.LINK) addView(ui.footnote(a.t("Ajouté par lien. Compare le numéro de sécurité pour le vérifier.", "Added by link. Compare the safety number to verify.")))
            if (c.state is FfiContactState.KeysChanged) addView(ui.footnote(a.t("Ses clés ont changé : ses partages attendent ta confirmation dans Clés changées.", "Their keys changed: their shares wait for your confirmation in Changed keys."), ui.orange))
            if (c.level == FfiContactLevel.LINK && c.safetyNumber.isNotBlank()) {
                addView(ui.inset(ui.card(ui.row(title = a.t("Comparer le numéro de sécurité", "Compare safety number")) { a.push { safetyNumberPage(c.accountId) } }), top = Ios.Space.L))
            }
            addView(ui.inset(ui.card(
                ui.row(title = a.t("Renommer", "Rename"), chevron = false, titleColor = ui.readableAccent) { rename(c) },
                ui.row(title = a.t("Retirer ce contact", "Remove contact"), chevron = false, titleColor = ui.red) {
                    a.confirm(a.t("Retirer ${c.nameLocal} de tes contacts ? Ce que tu partages avec ${c.nameLocal} s'arrête.", "Remove ${c.nameLocal} from your contacts? What you share with ${c.nameLocal} stops."), a.t("Retirer", "Remove")) {
                        act(work = { a.vault.session!!.removeContact(c.accountId, now()) }) { a.popNow() }
                    }
                },
            ), top = Ios.Space.XL))
            addView(ui.footnote(a.t("Ce nom reste sur tes appareils : il n'est jamais partagé.", "This name stays on your devices: it is never shared.")))
        }
    }

    private fun rename(c: FfiContact) {
        val field = EditText(a).apply { setText(c.nameLocal); setSelection(text.length) }
        AlertDialog.Builder(a).setTitle(a.t("Renommer", "Rename")).setView(LinearLayout(a).apply {
            setPadding(ui.dp(20), ui.dp(8), ui.dp(20), 0); addView(field, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        }).setPositiveButton("OK") { _, _ ->
            val n = field.text.toString().trim()
            if (n.isNotEmpty()) act(work = { a.vault.session!!.renameContact(c.accountId, n) })
        }.setNegativeButton(a.t("Annuler", "Cancel"), null).show()
    }

    /** "Comparer le numéro de sécurité" (spec 5.3.2): a match takes the contact from Link to Verified. */
    private fun safetyNumberPage(accountId: String): View = a.pushedPage(a.t("Comparer le numéro de sécurité", "Compare safety number")) {
        val c = snap.contact(accountId) ?: return@pushedPage
        addView(ui.capsLabel(a.t("Numéro de sécurité", "Safety number")))
        val groups = c.safetyNumber.trim().split(Regex("\\s+"))
        val lines = groups.chunked(4).joinToString("\n") { it.joinToString("  ") }
        addView(ui.inset(ui.card(ui.text(lines, 21f, ui.label, 600).apply {
            typeface = Typeface.create(Typeface.MONOSPACE, 600, false)
            gravity = Gravity.CENTER
            setLineSpacing(ui.dp(6).toFloat(), 1f)
            setTextIsSelectable(true)
            setPadding(ui.dp(12), ui.dp(18), ui.dp(12), ui.dp(18))
        })))
        addView(ui.footnote(a.t("Compare ce numéro avec celui affiché chez ${c.nameLocal}, de vive voix ou par appel.", "Compare this number with the one ${c.nameLocal} sees, in person or on a call.")))
        val err = errorLine()
        addView(ui.inset(ui.card(ui.row(title = a.t("Les numéros sont identiques", "The numbers match"), titleColor = ui.readableAccent, chevron = false) {
            act(err, { a.vault.session!!.confirmSafetyNumber(c.accountId, c.safetyNumber, now()) }) { a.popNow() }
        }), top = Ios.Space.L))
        addView(err)
    }

    // ---- invitation by link -----------------------------------------------------------------

    private fun myName(): String = a.profileName.ifBlank { android.os.Build.MODEL ?: "Android" }

    /** Draws `flow`'s state into `box` now and on each change while `d` shows. */
    private fun follow(d: Dialog, box: LinearLayout, flow: ContactInviteFlow?, intro: () -> Unit) {
        fun draw() {
            box.removeAllViews()
            when (val st = flow?.state) {
                null, ContactInviteFlow.State.Idle -> intro()
                is ContactInviteFlow.State.Sharing -> {
                    box.addView(ui.inset(ui.card(
                        ui.row(icon = ui.glyph(R.drawable.ic_share, ui.accent, 24), title = a.t("Envoyer le lien", "Send link"), titleColor = ui.readableAccent, chevron = false) {
                            a.startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply { type = "text/plain"; putExtra(Intent.EXTRA_TEXT, st.link) }, null))
                        },
                        ui.row(icon = ui.glyph(R.drawable.ic_copy, ui.accent, 24), title = a.t("Copier le lien", "Copy link"), titleColor = ui.readableAccent, chevron = false) { a.copy(st.link, true) },
                        ui.row(icon = ui.glyph(R.drawable.ic_hourglass, ui.secondary, 24), title = a.t("En attente de la réponse…", "Waiting for a reply…"), titleColor = ui.secondary, chevron = false),
                    ), top = Ios.Space.S))
                    box.addView(ui.footnote(a.t("Le lien expire après 24 heures. Un contact ajouté par lien n'a que la lecture tant qu'il n'est pas vérifié.", "The link expires after 24 hours. A contact added by link only gets Read until verified.")))
                }
                ContactInviteFlow.State.WaitingForAnswer -> box.addView(ui.inset(ui.card(
                    ui.row(icon = ui.glyph(R.drawable.ic_hourglass, ui.secondary, 24), title = a.t("En attente de la réponse…", "Waiting for a reply…"), titleColor = ui.secondary, chevron = false),
                ), top = Ios.Space.S))
                is ContactInviteFlow.State.Done -> {
                    box.addView(ui.inset(ui.card(ui.row(icon = avatar(st.contact.nameLocal), title = st.contact.nameLocal, chevron = false, trailing = unverifiedBadge())), top = Ios.Space.S))
                    box.addView(ui.inset(ui.card(ui.row(title = a.t("Comparer le numéro de sécurité", "Compare safety number")) {
                        d.dismiss()
                        a.vault.session?.let { sharing.readNow(it) }
                        a.push { safetyNumberPage(st.contact.accountId) }
                    }), top = Ios.Space.L))
                    box.addView(ui.footnote(a.t("Ajouté par lien. Compare le numéro de sécurité pour le vérifier.", "Added by link. Compare the safety number to verify.")))
                }
                is ContactInviteFlow.State.Failed -> {
                    box.addView(ui.footnote(message(st.error), ui.red))
                    box.addView(ui.inset(ui.card(ui.row(title = a.t("Réessayer", "Try Again"), titleColor = ui.readableAccent, chevron = false) { intro() }), top = Ios.Space.S))
                }
            }
        }
        val l: () -> Unit = { if (d.isShowing) draw() }
        sharing.onChange(l)
        d.setOnDismissListener { sharing.removeChange(l); a.render() }
        draw()
    }

    /** "Ajouter par lien": a new invitation shared with the system share sheet; the reply is awaited. */
    fun inviteByLink() {
        val box = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL; setPadding(0, ui.dp(8), 0, ui.dp(40)) }
        a.sheet(a.t("Ajouter par lien", "Add by link"), a.t("OK", "OK"), null) { d ->
            lateinit var intro: () -> Unit
            intro = {
                box.removeAllViews()
                box.addView(ui.inset(ui.card(ui.row(icon = ui.glyph(R.drawable.ic_link, ui.accent, 24), title = a.t("Créer un lien", "Create link"), titleColor = ui.readableAccent, chevron = false) {
                    val f = sharing.createInvite(myName())
                    if (f == null) a.toast(a.t("OnePass est verrouillé.", "OnePass is locked.")) else follow(d, box, f, intro)
                }), top = Ios.Space.S))
                box.addView(ui.footnote(a.t("Le lien expire après 24 heures. Un contact ajouté par lien n'a que la lecture tant qu'il n'est pas vérifié.", "The link expires after 24 hours. A contact added by link only gets Read until verified.")))
            }
            follow(d, box, sharing.inviter?.takeIf { it.state !is ContactInviteFlow.State.Failed }, intro)
            box
        }
    }

    /** "Ouvrir un lien d'invitation": a link received from a contact (pasted, or opened from another app). */
    fun openLink(link: String?) {
        val box = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL; setPadding(0, ui.dp(8), 0, ui.dp(40)) }
        a.sheet(a.t("Lien d'invitation", "Invitation link"), a.t("OK", "OK"), null) { d ->
            lateinit var intro: () -> Unit
            intro = {
                box.removeAllViews()
                val field = ui.field("onepass://contact…", link ?: "")
                box.addView(ui.inset(ui.card(field), top = Ios.Space.S))
                box.addView(ui.footnote(a.t("Colle le lien que ton contact t'a envoyé. OnePass lui répond ; vous serez contacts dès qu'il aura confirmé.", "Paste the link your contact sent you. OnePass answers it; you become contacts once they confirm.")))
                box.addView(ui.inset(ui.card(ui.row(title = a.t("Répondre à l'invitation", "Answer the invitation"), titleColor = ui.readableAccent, chevron = false) {
                    val text = field.text.toString().trim()
                    if (!text.startsWith("onepass://contact")) {
                        box.addView(ui.footnote(a.t("Ce lien d'invitation n'est pas valide.", "This invitation link is not valid."), ui.red))
                        return@row
                    }
                    val f = sharing.openLink(text, myName())
                    if (f == null) a.toast(a.t("OnePass est verrouillé.", "OnePass is locked.")) else follow(d, box, f, intro)
                }), top = Ios.Space.L))
            }
            intro()
            box
        }
    }

    // ---- invitations, received items, changed keys -----------------------------------------------------

    fun invitesPage(): View = a.pushedPage(a.t("Invitations", "Invitations"), largeTitle = true) {
        val err = errorLine()
        if (snap.shareInvites.isEmpty()) addView(ui.footnote(a.t("Aucune invitation.", "No invitations.")))
        snap.shareInvites.forEach { inv ->
            val what = inv.vaultNameHint?.let { a.t("${inv.fromNameLocal} t'invite dans « $it ».", "${inv.fromNameLocal} invites you to \"$it\".") }
                ?: a.t("${inv.fromNameLocal} t'invite dans un coffre.", "${inv.fromNameLocal} invites you to a vault.")
            addView(ui.inset(ui.card(
                ui.row(title = what, chevron = false),
                ui.row(title = a.t("Rôle", "Role"), value = roleTitle(inv.role), chevron = false),
                ui.row(title = a.t("Rejoindre", "Join"), titleColor = ui.readableAccent, chevron = false) {
                    act(err, { a.vault.session!!.acceptShareInvite(inv.id, now()) })
                },
                ui.row(title = a.t("Refuser", "Decline"), titleColor = ui.red, chevron = false) {
                    act(err, { a.vault.session!!.declineShareInvite(inv.id) })
                },
            ), top = Ios.Space.L))
        }
        addView(err)
    }

    private var receiveInto: String? = null

    fun receivedPage(): View = a.pushedPage(a.t("Éléments reçus", "Received items"), largeTitle = true) {
        val err = errorLine()
        val writable = a.vaults.filter { snap.role(it.id).let { r -> r == null || r != FfiRole.READ } }
        val into = writable.firstOrNull { it.id == receiveInto } ?: writable.firstOrNull()
        addView(ui.inset(ui.card(ui.row(title = a.t("Dans le coffre", "Into vault"), value = into?.meta?.name ?: "") {
            AlertDialog.Builder(a).setTitle(a.t("Dans le coffre", "Into vault"))
                .setItems(writable.map { it.meta.name }.toTypedArray()) { _, i -> receiveInto = writable[i].id; a.render() }.show()
        }), top = Ios.Space.S))
        if (snap.receivedItems.isEmpty()) addView(ui.footnote(a.t("Aucun élément reçu.", "No received items.")))
        snap.receivedItems.forEach { item ->
            addView(ui.inset(ui.card(
                ui.row(icon = a.itemIcon(item.kind, 30), title = item.title, value = a.t("De ${item.fromNameLocal}", "From ${item.fromNameLocal}"), chevron = false),
                ui.row(title = a.t("Garder", "Keep"), titleColor = ui.readableAccent, chevron = false) {
                    val target = into ?: return@row
                    act(err, { a.vault.session!!.acceptReceivedItem(item.sendId, target.id, now()) })
                },
                ui.row(title = a.t("Refuser", "Decline"), titleColor = ui.red, chevron = false) {
                    act(err, { a.vault.session!!.declineReceivedItem(item.sendId) })
                },
            ), top = Ios.Space.L))
        }
        addView(err)
    }

    private fun longDate(unix: Long): String =
        DateFormat.getDateInstance(DateFormat.LONG, a.resources.configuration.locales[0] ?: Locale.getDefault()).format(Date(unix * 1000))

    /** What to offer for a member's new keys (decision 6, C-2): the code for a reader, in person otherwise. */
    private fun offer(change: FfiIdentityChange): Pair<Boolean, String> {
        val name = change.nameLocal
        if (change.forked) return false to a.t("Deux appareils de $name se sont retirés l'un l'autre. Lequel a-t-elle encore en main ?", "Two of $name's devices removed each other. Which one do they still have?")
        val roles = snap.sharedVaults.filter { it.vaultId in change.vaults }.mapNotNull { v -> v.members.firstOrNull { it.accountId == change.accountId }?.role }
        val date = longDate(change.issuedAt)
        if (roles.any { it != FfiRole.READ }) return false to a.t("Les clés de $name ont changé le $date. Pour lui rendre l'accès, vérifiez-vous en personne avec le QR.", "$name's keys changed on $date. To give them access again, verify each other in person with the QR code.")
        val rotator = change.rotatorName
        if (rotator != null && change.revokedNames.isNotEmpty()) {
            val removed = change.revokedNames.joinToString(a.t(" et ", " and "))
            return true to a.t("Les clés de $name ont changé le $date ($rotator a retiré $removed). Demande-lui le code affiché sur son iPhone.", "$name's keys changed on $date ($rotator removed $removed). Ask them for the code shown on their iPhone.")
        }
        return true to a.t("Les clés de $name ont changé le $date. Demande-lui le code affiché sur son iPhone.", "$name's keys changed on $date. Ask them for the code shown on their iPhone.")
    }

    fun identityPage(): View = a.pushedPage(a.t("Clés changées", "Changed keys"), largeTitle = true) {
        val err = errorLine()
        snap.identityChanges.forEach { change ->
            val (byCode, text) = offer(change)
            val rows = mutableListOf<View>(ui.text(text, 15f, ui.label).apply { setPadding(ui.dp(16), ui.dp(12), ui.dp(16), ui.dp(12)) })
            if (byCode) {
                val code = ui.field(a.t("Code à 6 chiffres", "6-digit code")).apply { inputType = android.text.InputType.TYPE_CLASS_NUMBER }
                rows += code
                rows += ui.row(title = a.t("Confirmer", "Confirm"), titleColor = ui.readableAccent, chevron = false) {
                    val n = code.text.toString().trim().toUIntOrNull() ?: return@row
                    act(err, { a.vault.session!!.adoptMemberIdentity(change.accountId, change.child, FfiAdoptionProof.Code(n), now()) })
                }
            } else {
                rows += ui.text(a.t("La vérification en personne n'est pas encore sur Android : faites-la depuis un iPhone ou un Mac.", "In-person verification is not on Android yet: do it from an iPhone or a Mac."), 13f, ui.secondary).apply { setPadding(ui.dp(16), ui.dp(4), ui.dp(16), ui.dp(12)) }
            }
            addView(ui.inset(ui.card(*rows.toTypedArray()), top = Ios.Space.L))
        }
        addView(err)
    }

    // ---- banners (iPhone home) --------------------------------------------------------------------

    /** The sharing notices over the home page (spec 10.1, 11.5, 12.3, 14.2). Null when there is none. */
    fun banners(): View? {
        val s = snap
        val alerts = sharing.alerts
        if (alerts.isEmpty() && s.notices == 0) return null
        val col = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL; setPadding(ui.dp(16), ui.dp(4), ui.dp(16), ui.dp(4)) }
        alerts.forEach { col.addView(a.familyScreens.recoveryAlertBanner(it), spaced()) }
        fun row(title: String, icon: Int, open: () -> View) {
            val r = LinearLayout(a).apply {
                gravity = Gravity.CENTER_VERTICAL
                background = ui.pressable(ui.rounded(Color.argb(if (ui.dark) 0x33 else 0x1A, Color.red(ui.accent), Color.green(ui.accent), Color.blue(ui.accent)), 14), 14)
                setPadding(ui.dp(12), ui.dp(12), ui.dp(12), ui.dp(12))
                isClickable = true
                setOnClickListener { a.push(build = open) }
                addView(ui.glyph(icon, ui.accent, 22).apply { (layoutParams as LinearLayout.LayoutParams).marginEnd = ui.dp(10) })
                addView(ui.text(title, 16f, ui.label), LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
                addView(ui.glyph(R.drawable.ic_chevron_right, ui.tertiary, 18))
            }
            col.addView(r, spaced())
        }
        if (s.shareInvites.isNotEmpty()) row(a.t("Invitations à un coffre : ${s.shareInvites.size}", "Vault invitations: ${s.shareInvites.size}"), R.drawable.ic_person_add) { invitesPage() }
        if (s.identityChanges.isNotEmpty()) row(a.t("Clés changées : ${s.identityChanges.size}", "Changed keys: ${s.identityChanges.size}"), R.drawable.ic_key) { identityPage() }
        if (s.receivedItems.isNotEmpty()) row(a.t("Éléments reçus : ${s.receivedItems.size}", "Received items: ${s.receivedItems.size}"), R.drawable.ic_import) { receivedPage() }
        return col
    }

    private fun spaced() = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = ui.dp(8) }

    // ---- shared vaults ----------------------------------------------------------------------------------

    /** "Partage" of the vault editor (spec 10): the members of a shared vault, or "Partager ce coffre". */
    fun vaultSection(vaultId: String, close: () -> Unit): View {
        val shared = snap.shared(vaultId)
        return ui.card(
            if (shared != null) ui.row(icon = ui.glyph(R.drawable.ic_person_add, ui.accent, 24), title = a.t("Membres", "Members"), value = "${shared.members.size}") { close(); a.push { membersPage(vaultId) } }
            else ui.row(icon = ui.glyph(R.drawable.ic_person_add, ui.accent, 24), title = a.t("Partager ce coffre", "Share this vault"), titleColor = ui.readableAccent, chevron = false) { close(); shareSheet(vaultId) },
        )
    }

    fun membersPage(vaultId: String): View = a.pushedPage(a.t("Membres", "Members"), largeTitle = true) {
        val v = snap.shared(vaultId) ?: return@pushedPage
        val manages = v.role == FfiRole.MANAGE
        val err = errorLine()
        val me = a.vault.session?.let { runCatching { it.accountId() }.getOrNull() }
        val rows = v.members.map { m -> memberRow(vaultId, m, manages, m.accountId == me) }.toMutableList<View>()
        if (manages) rows += ui.row(icon = ui.glyph(R.drawable.ic_person_add, ui.accent, 24), title = a.t("Ajouter un membre", "Add member"), titleColor = ui.readableAccent, chevron = false) { shareSheet(vaultId) }
        addView(ui.inset(ui.card(*rows.toTypedArray()), top = Ios.Space.S))
        val notConfirmed = runCatching { a.vault.session?.membersNotConfirmed(vaultId) }.getOrNull().orEmpty()
        if (notConfirmed.isNotEmpty()) addView(ui.footnote(a.t("Pas encore confirmé : ${notConfirmed.size}", "Not confirmed yet: ${notConfirmed.size}")))
        if (v.identityPending) addView(ui.footnote(a.t("Des clés changées attendent ta confirmation.", "Changed keys wait for your confirmation.")))
        val refused = a.sync.zones?.refusals.orEmpty().any { it.zone.kind == FfiZoneKind.VAULT && it.zone.id == vaultId && !it.removed }
        if (refused) addView(ui.footnote(a.t("Le serveur refuse l'accès à ${v.name}.", "The server refuses access to ${v.name}."), ui.orange))
        val actions = mutableListOf<View>()
        if (v.owner && v.members.size == 1) actions += ui.row(title = a.t("Arrêter le partage", "Stop sharing"), titleColor = ui.readableAccent, chevron = false) {
            act(err, { a.vault.session!!.stopSharing(vaultId, now()) }) { a.popNow() }
        }
        if (!v.owner) actions += ui.row(title = a.t("Quitter le coffre", "Leave vault"), titleColor = ui.red, chevron = false) {
            a.confirm(a.t("Quitter « ${v.name} » ? Ses éléments disparaissent de tes appareils.", "Leave “${v.name}”? Its items leave your devices."), a.t("Quitter", "Leave")) {
                act(err, { a.vault.session!!.leaveSharedVault(vaultId, now()) }) { a.popNow() }
            }
        }
        if (actions.isNotEmpty()) addView(ui.inset(ui.card(*actions.toTypedArray()), top = Ios.Space.XL))
        addView(err)
    }

    private fun memberRow(vaultId: String, m: FfiMember, manages: Boolean, me: Boolean): View {
        val name = if (me || m.nameLocal.isEmpty()) a.t("Toi", "You") else m.nameLocal
        val sub = listOfNotNull(roleTitle(m.role), if (m.owner) a.t("Propriétaire", "Owner") else null,
            if (m.keysChanged) a.t("Ses clés ont changé", "Their keys changed") else null).joinToString(" · ")
        val canEdit = manages && !m.owner && !me && m.nameLocal.isNotEmpty()
        val badge = if (m.level == FfiContactLevel.LINK && !me && m.nameLocal.isNotEmpty()) unverifiedBadge() else null
        lateinit var row: LinearLayout
        row = ui.row(icon = avatar(name), title = name, subtitle = sub, trailing = badge, chevron = false, onClick = if (!canEdit) null else ({
            val entries = mutableListOf<Triple<Int, String, () -> Unit>>()
            val roles = if (m.level == FfiContactLevel.LINK) listOf(FfiRole.READ) else listOf(FfiRole.READ, FfiRole.WRITE, FfiRole.MANAGE)
            roles.filter { it != m.role }.forEach { r ->
                entries += Triple(R.drawable.ic_key, roleTitle(r)) { act(work = { a.vault.session!!.setRole(vaultId, m.accountId, r, now()) }) }
            }
            val remove = a.t("Retirer", "Remove")
            entries += Triple(R.drawable.ic_person_off, remove) { removeMember(vaultId, m) }
            a.menu(row, entries, setOf(remove))
        }))
        return row
    }

    /** "Partager ce coffre" and "Ajouter un membre" (spec 10): a contact and a role; a link contact gets Read only. */
    fun shareSheet(vaultId: String) {
        val members = snap.shared(vaultId)?.members?.map { it.accountId }.orEmpty().toSet()
        val contacts = snap.contacts.filter { it.state is FfiContactState.Active && it.accountId !in members }.sortedBy { it.nameLocal.lowercase() }
        var chosen: FfiContact? = null
        var role = FfiRole.READ
        val err = errorLine()
        val box = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL; setPadding(0, ui.dp(8), 0, ui.dp(40)) }
        fun draw() {
            box.removeAllViews()
            box.addView(ui.capsLabel(a.t("Contacts", "Contacts")))
            if (contacts.isEmpty()) box.addView(ui.footnote(a.t("Aucun contact. Ajoute d'abord un contact dans Réglages > Contacts.", "No contacts. First add one in Settings > Contacts.")))
            else box.addView(ui.inset(ui.card(*contacts.map { c ->
                ui.row(icon = avatar(c.nameLocal), title = c.nameLocal, chevron = false,
                    trailing = if (chosen?.accountId == c.accountId) ui.glyph(R.drawable.ic_check, ui.accent, 22) else if (c.level == FfiContactLevel.LINK) unverifiedBadge() else null) {
                    chosen = c
                    if (c.level == FfiContactLevel.LINK) role = FfiRole.READ
                    draw()
                }
            }.toTypedArray())))
            val roles = if (chosen?.level == FfiContactLevel.LINK) listOf(FfiRole.READ) else listOf(FfiRole.READ, FfiRole.WRITE, FfiRole.MANAGE)
            box.addView(ui.inset(ui.card(ui.row(title = a.t("Rôle", "Role"), value = roleTitle(role)) {
                AlertDialog.Builder(a).setTitle(a.t("Rôle", "Role")).setItems(roles.map { roleTitle(it) }.toTypedArray()) { _, i -> role = roles[i]; draw() }.show()
            }), top = Ios.Space.L))
            if (chosen?.level == FfiContactLevel.LINK) box.addView(ui.footnote(a.t("Un contact non vérifié n'a que la lecture.", "A contact that is not verified only gets Read.")))
            box.addView(err)
        }
        draw()
        var busy = false
        a.sheet(a.t("Ajouter un membre", "Add member"), a.t("Annuler", "Cancel"), a.t("Partager", "Share") to { d ->
            val c = chosen ?: return@to
            if (busy) return@to
            busy = true
            err.text = ""
            a.background({
                val s = a.vault.session ?: throw OnePassException.Locked()
                if (sharing.snapshot.role(vaultId) == null && s.sharedVaults().none { it.vaultId == vaultId }) {
                    s.shareVault(vaultId, now())
                    // The vault's mailbox is made by the zone round (spec 13.3).
                    a.sync.zones?.syncNow()
                }
                s.addMember(vaultId, c.accountId, role, now())
                a.sync.zones?.kick()
                sharing.readNow(s)
            }) { r ->
                busy = false
                r.onSuccess { d.dismiss(); a.sync.localChange(); a.reload { a.render() } }.onFailure { err.text = message(it) }
            }
        }) { box }
    }

    /** "Retirer" a member (spec 9.3): confirmed, then what they could read and "Changer les mots de passe". */
    private fun removeMember(vaultId: String, m: FfiMember) {
        val vaultName = snap.shared(vaultId)?.name ?: ""
        val box = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL; setPadding(0, ui.dp(8), 0, ui.dp(40)) }
        val err = errorLine()
        a.sheet(a.t("Retirer", "Remove"), a.t("Annuler", "Cancel"), null) { d ->
            box.addView(ui.inset(ui.card(ui.text(a.t("Retirer ${m.nameLocal} du coffre ?", "Remove ${m.nameLocal} from the vault?"), 17f, ui.label).apply { setPadding(ui.dp(16), ui.dp(14), ui.dp(16), ui.dp(14)) }), top = Ios.Space.S))
            box.addView(ui.footnote(a.t("Le coffre reçoit une nouvelle clé. Ce que ce membre a déjà vu reste vu.", "The vault gets a new key. What this member already saw stays seen.")))
            box.addView(ui.inset(ui.card(ui.row(title = a.t("Retirer", "Remove"), titleColor = ui.red, chevron = false) {
                a.background({
                    val s = a.vault.session ?: throw OnePassException.Locked()
                    s.removeMember(vaultId, m.accountId, now()).also { sharing.readNow(s) }
                }) { r ->
                    r.onSuccess { removal ->
                        a.sync.localChange()
                        box.removeAllViews()
                        val n = removal.seenItems.toInt()
                        box.addView(ui.inset(ui.card(ui.text(a.t("${m.nameLocal} ne verra plus rien de nouveau dans $vaultName. Il a pu garder ce qu'il a déjà vu : $n mots de passe. Les changer ?",
                            "${m.nameLocal} won't see anything new in $vaultName. They may have kept what they already saw: $n passwords. Change them?"), 17f, ui.label).apply { setPadding(ui.dp(16), ui.dp(14), ui.dp(16), ui.dp(14)) }), top = Ios.Space.S))
                        box.addView(ui.inset(ui.card(
                            ui.row(title = a.t("Changer les mots de passe", "Change passwords"), titleColor = ui.readableAccent, chevron = false) { d.dismiss(); seenByFormerMembers() },
                            ui.row(title = a.t("Plus tard", "Later"), titleColor = ui.readableAccent, chevron = false) { d.dismiss() },
                        ), top = Ios.Space.L))
                    }.onFailure { err.text = message(it) }
                }
            }), top = Ios.Space.L))
            box.addView(err)
            d.setOnDismissListener { a.reload { a.render() } }
            box
        }
    }

    /** Watchtower "Vus par un ancien membre": the items a removed member could read. */
    fun seenByFormerMembers() {
        val ids = snap.seenByFormerMembers
        val list = a.active.filter { it.id in ids }
        a.push {
            a.pushedPage(a.t("Vus par un ancien membre", "Seen by a former member"), largeTitle = true) {
                addView(ui.footnote(a.t("Un membre retiré a pu garder ces mots de passe. Change-les sur leurs sites.", "A removed member may have kept these passwords. Change them on their sites.")))
                addView(a.itemsCard(list, a.t("Rien à changer.", "Nothing to change.")))
            }
        }
    }

    // ---- send an item -------------------------------------------------------------------------------------

    /** "Envoyer à un contact" (spec 14.2): a copy of the item, kept for the contact until the date chosen. */
    fun sendItem(item: FfiItem) {
        val contacts = snap.contacts.filter { it.state is FfiContactState.Active }.sortedBy { it.nameLocal.lowercase() }
        var chosen: FfiContact? = null
        var days = 7
        val err = errorLine()
        val box = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL; setPadding(0, ui.dp(8), 0, ui.dp(40)) }
        fun draw() {
            box.removeAllViews()
            box.addView(ui.inset(ui.card(ui.row(icon = a.itemIcon(item.itemType, 30), title = item.title, chevron = false)), top = Ios.Space.S))
            box.addView(ui.capsLabel(a.t("Contacts", "Contacts")))
            if (contacts.isEmpty()) box.addView(ui.footnote(a.t("Aucun contact. Ajoute d'abord un contact dans Réglages > Contacts.", "No contacts. First add one in Settings > Contacts.")))
            else box.addView(ui.inset(ui.card(*contacts.map { c ->
                ui.row(icon = avatar(c.nameLocal), title = c.nameLocal, chevron = false,
                    trailing = if (chosen?.accountId == c.accountId) ui.glyph(R.drawable.ic_check, ui.accent, 22) else null) { chosen = c; draw() }
            }.toTypedArray())))
            val choices = listOf(1, 7, 30)
            fun label(n: Int) = if (n == 1) a.t("1 jour", "1 day") else a.t("$n jours", "$n days")
            box.addView(ui.inset(ui.card(ui.row(title = a.t("Disponible pendant", "Available for"), value = label(days)) {
                AlertDialog.Builder(a).setItems(choices.map { label(it) }.toTypedArray()) { _, i -> days = choices[i]; draw() }.show()
            }), top = Ios.Space.L))
            box.addView(ui.footnote(a.t("Ton contact reçoit une copie de cet élément. S'il ne la garde pas, elle disparaît à la fin du délai.", "Your contact gets a copy of this item. If they don't keep it, it disappears at the end of the period.")))
            box.addView(err)
        }
        draw()
        a.sheet(a.t("Envoyer à un contact", "Send to a Contact"), a.t("Annuler", "Cancel"), a.t("Envoyer", "Send") to { d ->
            val c = chosen ?: return@to
            a.background({
                val s = a.vault.session ?: throw OnePassException.Locked()
                val t = now()
                s.sendItem(item.vaultId, item.id, c.accountId, t + days * 86_400L, t)
            }) { r ->
                r.onSuccess {
                    d.dismiss()
                    a.sync.localChange()
                    a.toast(a.t("Envoyé à ${c.nameLocal}", "Sent to ${c.nameLocal}"))
                }.onFailure { err.text = message(it) }
            }
        }) { box }
    }
}
