package me.somalabs.onepass.screens

import android.app.AlertDialog
import android.graphics.Color
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import java.text.DateFormat
import java.util.Date
import java.util.Locale
import me.somalabs.onepass.MainActivity
import me.somalabs.onepass.R
import me.somalabs.onepass.core.FfiContactLevel
import me.somalabs.onepass.core.FfiContactState
import me.somalabs.onepass.core.FfiFamily
import me.somalabs.onepass.core.FfiFamilyMember
import me.somalabs.onepass.core.FfiFamilyRole
import me.somalabs.onepass.core.FfiHelper
import me.somalabs.onepass.core.FfiRecoveryAlert
import me.somalabs.onepass.core.FfiRecoveryStatus
import me.somalabs.onepass.core.OnePassException
import me.somalabs.onepass.ui.Ios

/**
 * Réglages > Famille as on iPhone (`App/Family`, spec 11): the members and
 * their roles, the reminder to add a second organizer, the invitations, the
 * family vaults, the recovery enrollment, the members who chose this account
 * as their organizer, and the recovery request shown on the member's devices.
 */
class FamilyScreens(private val a: MainActivity) {
    private val ui get() = a.ui
    private val snap get() = a.sharing.snapshot
    private fun now() = System.currentTimeMillis() / 1000
    private fun act(err: android.widget.TextView? = null, work: () -> Unit, done: () -> Unit = {}) = a.sharingScreens.act(err, work, done)

    private fun roleTitle(r: FfiFamilyRole) = if (r == FfiFamilyRole.ORGANIZER) a.t("Organisateur", "Organizer") else a.t("Membre", "Member")

    fun open() = a.push { page() }

    fun page(): View = a.pushedPage(a.t("Famille", "Family"), largeTitle = true) {
        val err = ui.footnote("", ui.red)
        val family = snap.family
        if (family != null) {
            if (family.needsSecondOrganizer) addView(ui.inset(ui.card(ui.row(icon = ui.glyph(R.drawable.ic_person_add, ui.orange, 24),
                title = a.t("Ajoute un deuxième organisateur pour que la famille ne dépende pas d'une seule personne.", "Add a second organizer so the family does not depend on one person."),
                titleColor = ui.orange, chevron = false)), top = Ios.Space.S))
            addView(ui.sectionHeader(a.t("Membres", "Members")))
            val me = runCatching { a.vault.session?.accountId() }.getOrNull()
            val rows = family.members.map { m -> memberRow(family, m, m.accountId == me, err) }.toMutableList<View>()
            if (family.iAmOrganizer) rows += ui.row(icon = ui.glyph(R.drawable.ic_person_add, ui.accent, 24), title = a.t("Inviter dans la famille", "Invite to family"), titleColor = ui.readableAccent, chevron = false) { inviteSheet() }
            addView(ui.inset(ui.card(*rows.toTypedArray())))

            // The family's shared vaults.
            addView(ui.sectionHeader(a.t("Coffres de la famille", "Family vaults")))
            val names = family.vaults.map { id -> a.vaults.firstOrNull { it.id == id }?.meta?.name ?: snap.shared(id)?.name ?: "…" }
            val vrows = family.vaults.zip(names).map { (id, name) ->
                ui.row(icon = ui.monogram(name.take(1).uppercase(), Ios.vaultColor(a.vaults.firstOrNull { it.id == id }?.meta?.color ?: "teal"), 30, square = true), title = name) {
                    a.push { a.sharingScreens.membersPage(id) }
                }
            }.toMutableList<View>()
            val personal = a.vaults.filter { v -> snap.role(v.id) == null }
            if (personal.size > 1) vrows += ui.row(title = a.t("Donner un coffre à la famille", "Give a vault to the family"), titleColor = ui.readableAccent, chevron = false) {
                AlertDialog.Builder(a).setTitle(a.t("Donner un coffre à la famille", "Give a vault to the family"))
                    .setItems(personal.map { it.meta.name }.toTypedArray()) { _, i -> act(err, { a.vault.session!!.addFamilyVault(personal[i].id, now()) }) }.show()
            }
            addView(ui.inset(ui.card(*vrows.toTypedArray())))

            recoverySection(family)
            if (snap.helpers.isNotEmpty()) {
                addView(ui.inset(ui.card(*snap.helpers.map { h ->
                    ui.row(title = helperMessage(h)) { a.push { helperPage(h) } }
                }.toTypedArray()), top = Ios.Space.XL))
            }
            addView(ui.inset(ui.card(ui.row(title = a.t("Quitter la famille", "Leave family"), titleColor = ui.red, chevron = false) {
                a.confirm(a.t("Quitter la famille ? Ses coffres disparaissent de tes appareils.", "Leave the family? Its vaults leave your devices."), a.t("Quitter", "Leave")) {
                    act(err, { a.vault.session!!.leaveFamily(now()) })
                }
            }), top = Ios.Space.XL))
        } else {
            addView(ui.inset(ui.card(
                ui.text(a.t("Aucune famille pour l'instant. Une famille partage un coffre et peut aider à récupérer un compte.", "No family yet. A family shares a vault and can help recover an account."), 15f, ui.secondary).apply { setPadding(ui.dp(16), ui.dp(14), ui.dp(16), ui.dp(14)) },
                ui.row(title = a.t("Créer une famille", "Create a family"), titleColor = ui.readableAccent, chevron = false) {
                    act(err, { a.vault.session!!.createFamily(a.t("Famille", "Family"), now()) })
                },
            ), top = Ios.Space.S))
        }
        if (snap.familyInvites.isNotEmpty()) {
            addView(ui.inset(ui.card(*snap.familyInvites.map { inv ->
                ui.row(title = a.t("Rejoindre la famille de ${inv.fromNameLocal}", "Join ${inv.fromNameLocal}'s family"), titleColor = ui.readableAccent, chevron = false) {
                    act(err, { a.vault.session!!.acceptFamilyInvite(inv.id, now()) })
                }
            }.toTypedArray()), top = Ios.Space.XL))
        }
        addView(err)
    }

    private fun memberRow(family: FfiFamily, m: FfiFamilyMember, isMe: Boolean, err: android.widget.TextView): View {
        val name = if (isMe || m.nameLocal.isEmpty()) a.t("Toi", "You") else m.nameLocal
        val canEdit = family.iAmOrganizer && !isMe && m.nameLocal.isNotEmpty()
        lateinit var row: LinearLayout
        row = ui.row(title = name, value = roleTitle(m.role), subtitle = if (m.keysChanged) a.t("Ses clés ont changé", "Their keys changed") else null,
            trailing = if (m.level == FfiContactLevel.LINK && !isMe) a.sharingScreens.unverifiedBadge() else null,
            chevron = false, onClick = if (!canEdit) null else ({
                val other = if (m.role == FfiFamilyRole.ORGANIZER) FfiFamilyRole.MEMBER else FfiFamilyRole.ORGANIZER
                val remove = a.t("Retirer de la famille", "Remove from family")
                a.menu(row, listOf(
                    Triple(R.drawable.ic_key, roleTitle(other)) { act(err, { a.vault.session!!.setFamilyRole(m.accountId, other, now()) }) },
                    Triple(R.drawable.ic_person_off, remove) {
                        a.confirm(a.t("Retirer ${m.nameLocal} de la famille ?", "Remove ${m.nameLocal} from the family?"), a.t("Retirer", "Remove")) {
                            act(err, { a.vault.session!!.removeFromFamily(m.accountId, now()) })
                        }
                    },
                ), setOf(remove))
            }))
        return row
    }

    /** Invite a contact into the family, as a member or an organizer (an organizer must be verified). */
    private fun inviteSheet() {
        val err = ui.footnote("", ui.red)
        val inFamily = snap.family?.members?.map { it.accountId }.orEmpty().toSet()
        val contacts = snap.contacts.filter { it.state is FfiContactState.Active && it.accountId !in inFamily }.sortedBy { it.nameLocal.lowercase() }
        a.sheet(a.t("Inviter dans la famille", "Invite to family"), a.t("Annuler", "Cancel"), null) { d ->
            LinearLayout(a).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(0, ui.dp(8), 0, ui.dp(40))
                if (contacts.isEmpty()) addView(ui.footnote(a.t("Aucun contact. Ajoute d'abord un contact dans Réglages > Contacts.", "No contacts. First add one in Settings > Contacts.")))
                else addView(ui.inset(ui.card(*contacts.map { c ->
                    lateinit var r: LinearLayout
                    r = ui.row(title = c.nameLocal, trailing = if (c.level == FfiContactLevel.LINK) a.sharingScreens.unverifiedBadge() else null, chevron = false) {
                        a.menu(r, listOf(FfiFamilyRole.MEMBER, FfiFamilyRole.ORGANIZER).map { role ->
                            Triple(R.drawable.ic_person_add, roleTitle(role)) {
                                a.background({ a.vault.session!!.inviteToFamily(c.accountId, role, now()); a.sharing.readNow(a.vault.session) }) { res ->
                                    res.onSuccess { d.dismiss(); a.sync.localChange(); a.render() }.onFailure { err.text = a.sharingScreens.message(it) }
                                }
                            }
                        })
                    }
                    r
                }.toTypedArray()), top = Ios.Space.S))
                addView(err)
            }
        }
    }

    // ---- recovery, member side ------------------------------------------------------------------------

    private fun LinearLayout.recoverySection(family: FfiFamily) {
        val e = snap.recoveryEnrollment
        val rows = mutableListOf<View>()
        if (e != null) {
            rows += ui.row(title = a.t("Organisateur choisi", "Chosen organizer"), value = e.organizerNameLocal, chevron = false)
            if (!e.valid) rows += ui.row(title = a.t("Des clés ont changé : choisis à nouveau ton organisateur.", "Keys changed: choose your organizer again."), titleColor = ui.orange, chevron = false) { enrollSheet() }
        } else if (!family.iAmOrganizer || family.members.count { it.role == FfiFamilyRole.ORGANIZER } > 1) {
            rows += ui.row(title = a.t("Récupération par un organisateur", "Recovery by an organizer"), titleColor = ui.readableAccent, chevron = false) { enrollSheet() }
        }
        if (rows.isEmpty()) return
        addView(ui.sectionHeader(a.t("Récupération du compte", "Account recovery")))
        addView(ui.inset(ui.card(*rows.toTypedArray())))
    }

    /** Enrollment (spec 11.4): the organizer, the delay, the risk sentence confirmed, then the master password. */
    private fun enrollSheet() {
        val me = runCatching { a.vault.session?.accountId() }.getOrNull()
        val organizers = snap.family?.members.orEmpty().filter { it.role == FfiFamilyRole.ORGANIZER && it.accountId != me && it.nameLocal.isNotEmpty() }
        var organizer = organizers.firstOrNull()
        var days = 3
        var understood = false
        val password = ui.field(a.t("Mot de passe principal", "Master password"), password = true)
        val err = ui.footnote("", ui.red)
        val box = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL; setPadding(0, ui.dp(8), 0, ui.dp(40)) }
        fun draw() {
            box.removeAllViews()
            if (organizers.isEmpty()) {
                box.addView(ui.footnote(a.t("Ta famille n'a pas encore d'autre organisateur.", "Your family has no other organizer yet.")))
                return
            }
            box.addView(ui.inset(ui.card(
                ui.row(title = a.t("Organisateur", "Organizer"), value = organizer?.nameLocal ?: "") {
                    AlertDialog.Builder(a).setItems(organizers.map { it.nameLocal }.toTypedArray()) { _, i -> organizer = organizers[i]; draw() }.show()
                },
                ui.row(title = a.t("Délai : $days jours", "Delay: $days days"), chevron = false, trailing = LinearLayout(a).apply {
                    addView(ui.capsule("−", prominent = false) { if (days > 1) { days--; draw() } }.apply { setPadding(ui.dp(16), ui.dp(4), ui.dp(16), ui.dp(4)); minHeight = ui.dp(34) })
                    addView(View(a), LinearLayout.LayoutParams(ui.dp(8), 1))
                    addView(ui.capsule("+", prominent = false) { if (days < 7) { days++; draw() } }.apply { setPadding(ui.dp(16), ui.dp(4), ui.dp(16), ui.dp(4)); minHeight = ui.dp(34) })
                }),
            ), top = Ios.Space.S))
            organizer?.let { o ->
                box.addView(ui.inset(ui.card(
                    ui.text(a.t("${o.nameLocal} et quelqu'un qui aurait ton Emergency Kit pourraient ensemble ouvrir ton coffre.", "${o.nameLocal} and someone with your Emergency Kit could open your vault together."), 15f, ui.label).apply { setPadding(ui.dp(16), ui.dp(14), ui.dp(16), ui.dp(14)) },
                    ui.toggleRow(a.t("J'ai compris", "I understand"), on = understood) { understood = it; draw() },
                ), top = Ios.Space.L))
            }
            if (understood) box.addView(ui.inset(ui.card(password), top = Ios.Space.L))
            box.addView(err)
        }
        draw()
        a.sheet(a.t("Récupération par un organisateur", "Recovery by an organizer"), a.t("Annuler", "Cancel"), a.t("Activer", "Turn on") to { d ->
            val o = organizer ?: return@to
            val pw = password.text.toString()
            if (!understood || pw.isEmpty()) return@to
            password.setText("")
            a.background({
                val s = a.vault.session ?: throw OnePassException.Locked()
                s.enrollRecovery(o.accountId, (days * 86_400).toUInt(), pw, a.vault.secretKey(), now())
                a.sharing.readNow(s)
            }) { r ->
                r.onSuccess { d.dismiss(); a.sync.localChange(); a.render() }.onFailure { err.text = a.sharingScreens.message(it) }
            }
        }) { box }
    }

    // ---- recovery, organizer side ----------------------------------------------------------------------

    private fun helperMessage(h: FfiHelper) = a.t("${h.nameLocal} t'a choisi pour l'aider à récupérer son compte.", "${h.nameLocal} chose you to help recover their account.")

    private fun dateTime(unix: Long): String {
        val loc = a.resources.configuration.locales[0] ?: Locale.getDefault()
        return DateFormat.getDateTimeInstance(DateFormat.LONG, DateFormat.SHORT, loc).format(Date(unix * 1000))
    }

    private fun helperPage(h: FfiHelper): View = a.pushedPage(a.t("Récupération du compte", "Account recovery")) {
        addView(ui.inset(ui.card(ui.text(helperMessage(h), 17f, ui.label).apply { setPadding(ui.dp(16), ui.dp(14), ui.dp(16), ui.dp(14)) }), top = Ios.Space.S))
        val err = ui.footnote("", ui.red)
        val status = runCatching { a.vault.session?.recoveryStatus(h.member, now()) }.getOrNull()
        when (status) {
            is FfiRecoveryStatus.Waiting -> addView(ui.footnote(a.t("Possible à partir du ${dateTime(status.releaseAfter)}.", "Possible from ${dateTime(status.releaseAfter)}.")))
            FfiRecoveryStatus.Ready -> {
                addView(ui.footnote(a.t("Le délai est passé. Scanne le code affiché sur le nouvel appareil du membre, en face à face.", "The delay is over. Scan the code on the member's new device, face to face.")))
                addView(ui.footnote(a.t("Le scan du code n'est pas encore sur Android : fais la remise depuis un iPhone ou un Mac.", "Scanning the code is not on Android yet: hand it over from an iPhone or a Mac."), ui.orange))
            }
            is FfiRecoveryStatus.Cancelled -> addView(ui.footnote(a.t("Le membre a annulé la récupération.", "The member cancelled the recovery.")))
            else -> {
                val pw = ui.field(a.t("Mot de passe principal", "Master password"), password = true)
                addView(ui.inset(ui.card(pw, ui.row(title = a.t("Demander la récupération", "Request recovery"), titleColor = ui.readableAccent, chevron = false) {
                    val p = pw.text.toString()
                    if (p.isEmpty()) return@row
                    pw.setText("")
                    act(err, { a.vault.session!!.requestRecovery(h.member, p, a.vault.secretKey(), now()) })
                }), top = Ios.Space.L))
                addView(ui.footnote(a.t("Le membre est prévenu sur tous ses appareils et peut annuler pendant le délai.", "The member is told on all their devices and can cancel during the delay.")))
            }
        }
        addView(err)
    }

    /** A recovery asked by an organizer (spec 11.5), on every device of the member: "Annuler" signs with this device's keys. */
    fun recoveryAlertBanner(alert: FfiRecoveryAlert): View {
        val loc = a.resources.configuration.locales[0] ?: Locale.getDefault()
        val at = Date(alert.releaseAfter * 1000)
        val date = DateFormat.getDateInstance(DateFormat.LONG, loc).format(at)
        val time = DateFormat.getTimeInstance(DateFormat.SHORT, loc).format(at)
        val col = LinearLayout(a).apply {
            orientation = LinearLayout.VERTICAL
            background = ui.rounded(Color.argb(0x1F, Color.red(ui.orange), Color.green(ui.orange), Color.blue(ui.orange)), 14)
            setPadding(ui.dp(14), ui.dp(14), ui.dp(14), ui.dp(10))
        }
        val head = LinearLayout(a).apply { gravity = Gravity.TOP }
        head.addView(ui.glyph(R.drawable.ic_shield_check, ui.orange, 22).apply { (layoutParams as LinearLayout.LayoutParams).marginEnd = ui.dp(10) })
        head.addView(ui.text(a.t("${alert.organizerNameLocal} a demandé à récupérer ton compte. Ce sera possible le $date à $time. Si ce n'est pas toi, annule.",
            "${alert.organizerNameLocal} asked to recover your account. It will be possible on $date at $time. If this isn't you, cancel."), 15f, ui.label),
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        col.addView(head)
        val err = ui.text("", 13f, ui.red)
        col.addView(ui.text(a.t("Annuler la récupération", "Cancel recovery"), 16f, ui.red, 600).apply {
            setPadding(ui.dp(32), ui.dp(10), 0, ui.dp(4))
            isClickable = true
            setOnClickListener {
                a.background({ a.sharing.cancelRecovery(alert.enrollmentId) }) { r ->
                    r.onSuccess { a.render() }.onFailure { err.text = a.sharingScreens.message(it) }
                }
            }
        })
        col.addView(err)
        return col
    }
}
