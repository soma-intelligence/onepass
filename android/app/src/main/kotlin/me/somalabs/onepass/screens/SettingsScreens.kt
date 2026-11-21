package me.somalabs.onepass.screens

import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.provider.Settings
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import java.text.DateFormat
import java.util.Date
import me.somalabs.onepass.MainActivity
import me.somalabs.onepass.R
import me.somalabs.onepass.core.FfiVault
import me.somalabs.onepass.core.FfiVaultMeta
import me.somalabs.onepass.ui.Ios
import me.somalabs.onepass.ui.RxArt
import me.somalabs.onepass.ui.heroPage
import me.somalabs.onepass.ui.rxCard
import me.somalabs.onepass.ui.rxRow
import me.somalabs.onepass.wifi.SuggestionApproval
import me.somalabs.onepass.wifi.SyncReport

/**
 * Réglages as on iPhone (SettingsView): the account on top, then the pages in
 * grouped cards with their drawn tiles. Pages whose feature Android does not
 * have yet (crypto tracking) say so plainly.
 */
class SettingsScreens(private val a: MainActivity) {
    private val ui get() = a.ui

    private class Page(val key: String, val art: Int, val fr: String, val en: String)

    private val groups = listOf(
        listOf(
            Page("general", R.drawable.settings_general, "Général", "General"),
            Page("security", R.drawable.settings_security, "Sécurité", "Security"),
            Page("autofill", R.drawable.settings_autofill, "Remplissage automatique", "AutoFill"),
            Page("sync", R.drawable.settings_sync, "Sync", "Sync"),
        ),
        listOf(
            Page("accounts", R.drawable.settings_accounts, "Comptes", "Accounts"),
            Page("vaults", R.drawable.settings_vaults, "Coffres", "Vaults"),
            Page("contacts", R.drawable.settings_contacts, "Contacts", "Contacts"),
            Page("family", R.drawable.settings_family, "Famille", "Family"),
            Page("devices", R.drawable.settings_devices, "Appareils", "Devices"),
            Page("travel", R.drawable.settings_travel, "Travel Mode", "Travel Mode"),
            Page("crypto", R.drawable.settings_crypto, "Crypto", "Crypto"),
            Page("developer", R.drawable.settings_developer, "Agents", "Agents"),
        ),
        listOf(Page("about", R.drawable.settings_about, "À propos", "About")),
    )

    private fun tile(res: Int) = a.itemIconArt(res, 30)

    fun open() = a.push { root() }

    /**
     * Réglages in the RX look (RXSettingsView): the profile over the photo (close button, the
     * initials in a ringed disc, the name, "Appareil personnel"), then the groups on the sheet.
     */
    private fun root(): View {
        val name = a.profileName
        val initials = name.split(" ").filter { it.isNotBlank() }.take(2).joinToString("") { it.first().uppercase() }.ifEmpty { "1" }
        return a.heroPage(RxArt.settings, darkPhoto = true, hero = {
            addView(LinearLayout(a).apply {
                addView(ui.roundButton(R.drawable.ic_close, a.t("Fermer", "Close")) { a.pop() }.apply {
                    background = ui.rounded(Color.argb(0x33, 255, 255, 255), 22, Color.argb(0x33, 255, 255, 255))
                    (getChildAt(0) as android.widget.ImageView).imageTintList = android.content.res.ColorStateList.valueOf(Color.WHITE)
                })
            })
            val avatar = TextView(a).apply {
                text = initials
                textSize = 36f
                typeface = ui.font(700)
                setTextColor(Color.WHITE)
                gravity = Gravity.CENTER
                background = android.graphics.drawable.GradientDrawable(android.graphics.drawable.GradientDrawable.Orientation.TL_BR, intArrayOf(Color.rgb(0x7B, 0x79, 0xF0), ui.accent)).apply {
                    shape = android.graphics.drawable.GradientDrawable.OVAL
                    setStroke(ui.dp(3), Color.argb(0x66, 255, 255, 255))
                }
                isClickable = true
                contentDescription = a.t("Profil", "Profile")
                setOnClickListener { a.push { accounts() } }
            }
            addView(avatar, LinearLayout.LayoutParams(ui.dp(96), ui.dp(96)).apply { gravity = Gravity.CENTER_HORIZONTAL; topMargin = ui.dp(24) })
            addView(ui.text(name.ifEmpty { a.t("Compte OnePass", "OnePass Account") }, 28f, Color.WHITE, 700).apply { gravity = Gravity.CENTER; maxLines = 2; setPadding(0, ui.dp(14), 0, ui.dp(4)) },
                LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
            addView(ui.text(a.t("Appareil personnel", "Personal device"), 17f, Color.argb(0xCC, 255, 255, 255)).apply { gravity = Gravity.CENTER },
                LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        }) {
            addView(ui.rxCard {
                setPadding(0, ui.dp(Ios.Space.S), 0, ui.dp(Ios.Space.S))
                addView(ui.rxRow(a.itemIconArt(R.drawable.settings_accounts, 30), a.t("Profil et Emergency Kit", "Profile and Emergency Kit"), chevron = true) { a.push { accounts() } })
            })
            groups.forEach { group ->
                addView(ui.rxCard {
                    setPadding(0, ui.dp(Ios.Space.S), 0, ui.dp(Ios.Space.S))
                    group.forEach { p -> addView(ui.rxRow(tile(p.art), a.t(p.fr, p.en), chevron = true) { if (p.key == "travel") a.travel.open() else a.push { page(p) } }) }
                })
            }
        }
    }

    private fun page(p: Page): View = when (p.key) {
        "general" -> general()
        "security" -> security()
        "vaults" -> vaults()
        "accounts" -> accounts()
        "devices" -> a.pairing.devices()
        "sync" -> a.syncScreens.page()
        "about" -> about()
        "autofill" -> autofill()
        "contacts" -> a.sharingScreens.contactsPage()
        "family" -> a.familyScreens.page()
        else -> notYet(p)
    }

    // ---- Remplissage automatique ------------------------------------------------------------------

    private fun autofillOn(): Boolean? = runCatching {
        a.getSystemService(android.view.autofill.AutofillManager::class.java)?.hasEnabledAutofillServices()
    }.getOrNull()

    /** As on iPhone: OnePass as the system's AutoFill provider, then what it learns from the user's choices. */
    private fun autofill(): View = a.pushedPage(a.t("Remplissage automatique", "AutoFill"), largeTitle = true) {
        val on = autofillOn()
        addView(ui.footnote(a.t("Identifiants, codes et passkeys, dans les apps et les navigateurs.", "Logins, codes and passkeys, in apps and browsers.")))
        val rows = mutableListOf<View>(ui.row(icon = a.itemIconArt(R.mipmap.ic_launcher, 30), title = "OnePass",
            value = when (on) { true -> a.t("Activé", "On"); false -> a.t("Désactivé", "Off"); null -> "" }, chevron = false))
        rows += ui.row(title = if (on == true) a.t("Gérer dans les réglages du système", "Manage in System Settings") else a.t("Activer OnePass", "Turn On OnePass"),
            titleColor = ui.readableAccent, chevron = false) {
            val i = Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE, Uri.parse("package:" + a.packageName))
            a.launch(i) { _, _ -> a.render() }
        }
        if (android.os.Build.VERSION.SDK_INT >= 34) rows += ui.row(icon = ui.symbolTile(R.drawable.ic_passkey, ui.accent), title = a.t("Passkeys et mots de passe", "Passkeys and Passwords"),
            subtitle = a.t("Gestionnaire d'identifiants Android", "Android Credential Manager")) {
            runCatching { a.startActivity(Intent("android.settings.CREDENTIAL_PROVIDER", Uri.parse("package:" + a.packageName))) }
                .onFailure { runCatching { a.startActivity(Intent(Settings.ACTION_SETTINGS)) } }
        }
        addView(ui.inset(ui.card(*rows.toTypedArray()), top = Ios.Space.S))
        addView(ui.footnote(if (on == true) a.t("Touche un champ d'identifiant : OnePass propose tes comptes.", "Tap a username field: OnePass offers your accounts.")
        else a.t("Sinon : Réglages du système > Mots de passe et saisie automatique.", "Otherwise: System Settings > Passwords & autofill.")))

        val s = a.vault.session ?: return@pushedPage
        // Learn from my choices, and the sites remembered.
        val history = runCatching { s.autofillHistoryEnabled() }.getOrDefault(true)
        addView(ui.inset(ui.card(
            ui.toggleRow(a.t("Apprendre de mes choix", "Learn from my choices"), on = history) { v -> a.background({ s.setAutofillHistoryEnabled(v) }) { } },
            ui.row(title = a.t("Effacer l'historique de remplissage", "Clear autofill history"), titleColor = ui.red, chevron = false) {
                a.confirm(a.t("Effacer l'historique de remplissage de cet appareil ?", "Clear this device's autofill history?"), a.t("Effacer", "Erase")) {
                    a.background({ s.clearAutofillHistory() }) { a.toast(a.t("Historique effacé", "History cleared")) }
                }
            },
        ), top = Ios.Space.XL))
        addView(ui.footnote(a.t("OnePass retient quel compte tu choisis sur chaque site ou app, pour le proposer en premier. Cet historique reste chiffré sur cet appareil : il n'est jamais synchronisé ni envoyé. Désactivé, il est effacé.",
            "OnePass remembers which account you pick on each site or app, to offer it first. This history stays encrypted on this device: it is never synced or sent. Turned off, it is erased.")))
        addView(ui.inset(ui.card(ui.row(title = a.t("Comptes retenus par site", "Remembered Accounts")) { a.push { remembered() } }), top = Ios.Space.L))
        addView(ui.footnote(a.t("Le compte choisi sur un site est proposé en premier.", "The account you pick on a site comes first next time.")))
    }

    private fun remembered(): View = a.pushedPage(a.t("Comptes retenus", "Remembered Accounts"), largeTitle = true) {
        val s = a.vault.session ?: return@pushedPage
        val sites = runCatching { s.knownUsageSites(emptyList()) }.getOrDefault(emptyList())
        if (sites.isEmpty()) addView(ui.footnote(a.t("Aucun site retenu pour l'instant.", "No site remembered yet.")))
        else addView(ui.inset(ui.card(*sites.map { site ->
            ui.row(title = site.removePrefix("app:"), subtitle = if (site.startsWith("app:")) a.t("app", "App") else null, chevron = false,
                trailing = ui.text(a.t("Oublier", "Forget"), 17f, ui.red).apply { setPadding(ui.dp(8), 0, ui.dp(4), 0) }) {
                a.confirm(a.t("Oublier $site ?", "Forget $site?"), a.t("Oublier", "Forget")) {
                    a.background({ s.forgetSiteUsage(site, emptyList()) }) { a.render() }
                }
            }
        }.toTypedArray()), top = Ios.Space.S))
        addView(ui.footnote(a.t("Oublier un site efface son choix sur tous tes appareils. Tes Logins ne changent pas.", "Forgetting a site clears its choice on all your devices. Your Logins stay.")))
    }

    private fun notYet(p: Page): View {
        val why = when (p.key) {
            "autofill" -> a.t("Le remplissage automatique d'Android (service Autofill et passkeys) arrive dans une prochaine version. En attendant, copie un identifiant depuis l'élément : il est effacé du presse-papiers après 90 secondes.",
                "Android AutoFill (the Autofill service and passkeys) comes in a later version. Meanwhile, copy a value from the item: it is cleared from the clipboard after 90 seconds.")
            "crypto" -> a.t("Les portefeuilles crypto se rangent déjà comme éléments. Le suivi des soldes arrive sur Android.",
                "Crypto wallets can already be stored as items. Balance tracking is coming to Android.")
            else -> a.t("Les agents (MCP, ssh-agent) tournent sur ordinateur, pas sur Android.", "Agents (MCP, ssh-agent) run on computers, not on Android.")
        }
        return a.pushedPage(a.t(p.fr, p.en), largeTitle = true) {
            addView(ui.inset(ui.card(LinearLayout(a).apply {
                gravity = Gravity.CENTER_VERTICAL
                setPadding(ui.dp(16), ui.dp(16), ui.dp(16), ui.dp(16))
                addView(tile(p.art).apply { (layoutParams as LinearLayout.LayoutParams).marginEnd = ui.dp(14) })
                addView(ui.text(why, 15f, ui.secondary), LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            })))
        }
    }

    // ---- Général ------------------------------------------------------------------------------------

    private var wifiStatus: TextView? = null

    private fun general(): View = a.pushedPage(a.t("Général", "General"), largeTitle = true) {
        addView(ui.inset(ui.card(
            ui.row(title = a.t("Verrouillage automatique", "Auto-Lock"), value = a.t("5 minutes", "5 minutes"), chevron = false),
            ui.row(title = a.t("Langue", "Language"), value = a.t("Français", "English")) {
                runCatching { a.startActivity(Intent(Settings.ACTION_APP_LOCALE_SETTINGS, Uri.fromParts("package", a.packageName, null))) }
            },
        ), top = Ios.Space.S))
        addView(ui.footnote(a.t("OnePass se verrouille après 5 minutes sans utilisation.", "OnePass locks after 5 minutes of inactivity.")))
        addView(ui.sectionHeader("Wi-Fi"))
        val status = ui.text("", 13f, ui.secondary).apply { setPadding(ui.dp(16), 0, ui.dp(16), ui.dp(12)) }
        wifiStatus = status
        addView(ui.inset(ui.card(
            ui.toggleRow(a.t("Connexion Wi-Fi automatique", "Automatic Wi-Fi"), a.t("Les réseaux de tes éléments Routeur Wi-Fi", "Networks from your Wi-Fi router items"), a.wifi.enabled) { a.wifi.enabled = it },
            status,
            ui.row(title = a.t("Réseaux Wi-Fi", "Wi-Fi Networks")) { a.push { wifiNetworks() } },
        )))
        attachWifi()
        a.backups.sections(this)
    }

    /** The networks of the Wi-Fi router items (`wifi_networks`), what automatic Wi-Fi installs. */
    private fun wifiNetworks(): View = a.pushedPage(a.t("Réseaux Wi-Fi", "Wi-Fi Networks"), largeTitle = true) {
        val sel = runCatching { a.vault.session?.wifiNetworks(emptyList()) }.getOrNull()
        val nets = sel?.networks.orEmpty()
        if (nets.isEmpty()) addView(ui.footnote(a.t("Aucun réseau : ajoute un élément Routeur Wi-Fi avec son nom de réseau et son mot de passe.", "No network: add a Wi-Fi Router item with its network name and password.")))
        else addView(ui.inset(ui.card(*nets.sortedBy { it.ssid.lowercase() }.map { n ->
            val sum = a.summaries.firstOrNull { it.id == n.itemId }
            ui.row(icon = ui.glyph(R.drawable.ic_wifi, ui.accent, 24), title = n.ssid,
                subtitle = listOfNotNull(n.security.name.replace('_', ' '), if (n.hidden) a.t("masqué", "hidden") else null, sum?.title).joinToString(" · ")) {
                sum?.let { a.items.detail(it.vaultId, it.id) }
            }
        }.toTypedArray()), top = Ios.Space.S))
        val skipped = sel?.skipped.orEmpty().values.sumOf { it.toInt() }
        if (skipped > 0) addView(ui.footnote(a.t("$skipped éléments Routeur laissés de côté (nom de réseau ou mot de passe manquant, ou sécurité non prise en charge).", "$skipped router items left out (missing network name or password, or unsupported security).")))
        addView(ui.footnote(a.t("Avec la connexion Wi-Fi automatique, Android rejoint ces réseaux quand ils sont à portée.", "With automatic Wi-Fi, Android joins these networks when they are in range.")))
    }

    private fun renderWifi(report: SyncReport?) {
        val status = wifiStatus ?: return
        status.setOnClickListener(null)
        status.text = when {
            report == null -> a.getString(R.string.wifi_auto_idle)
            !report.enabled -> a.getString(R.string.wifi_auto_off)
            report.failure != null -> a.getString(R.string.wifi_auto_failed, report.failure)
            report.installed == 0 -> a.getString(R.string.wifi_auto_none)
            report.approval == SuggestionApproval.REJECTED -> {
                status.setOnClickListener {
                    a.startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", a.packageName, null)))
                }
                a.getString(R.string.wifi_auto_rejected)
            }
            report.approval == SuggestionApproval.PENDING ->
                a.resources.getQuantityString(R.plurals.wifi_auto_installed, report.installed, report.installed) + "\n" + a.getString(R.string.wifi_auto_pending)
            else -> a.resources.getQuantityString(R.plurals.wifi_auto_installed, report.installed, report.installed)
        }
    }

    private fun attachWifi() {
        a.wifi.onReport = { r: SyncReport -> renderWifi(r) }
        renderWifi(a.wifi.lastReport)
        a.wifi.refresh()
    }

    /** Android's own "allow suggestions" dialog pauses the activity: re-attach on resume. */
    fun onResume() {
        if (wifiStatus?.isAttachedToWindow == true) attachWifi()
    }

    // ---- Sécurité -----------------------------------------------------------------------------------

    private fun security(): View = a.pushedPage(a.t("Sécurité", "Security"), largeTitle = true) {
        addView(ui.inset(ui.card(
            ui.row(icon = ui.symbolTile(R.drawable.ic_key, Color.rgb(224, 148, 0)), title = a.t("Changer le mot de passe maître", "Change Master Password")) { changePassword() },
            ui.row(icon = ui.symbolTile(R.drawable.ic_lock, ui.accent), title = a.t("Verrouiller maintenant", "Lock Now"), chevron = false) { a.lockNow() },
        ), top = Ios.Space.S))
        val info = ui.footnote("")
        addView(info)
        // Unlock with fingerprint or face (iPhone: "Déverrouiller avec Face ID").
        val bio = a.vault.biometrics
        val avail = bio.availability()
        addView(ui.sectionHeader(a.t("Déverrouillage", "Unlock")))
        lateinit var bioRow: LinearLayout
        bioRow = ui.toggleRow(a.t("Déverrouiller avec la biométrie", "Unlock with Biometrics"), on = bio.enrolled && avail == me.somalabs.onepass.vault.BiometricUnlock.Availability.AVAILABLE) { on ->
            if (on && !bio.enrolled) enableBiometrics(bioRow.getChildAt(bioRow.childCount - 1) as android.widget.Switch) else if (!on) bio.disable()
        }
        val sw = bioRow.getChildAt(bioRow.childCount - 1)
        if (avail != me.somalabs.onepass.vault.BiometricUnlock.Availability.AVAILABLE) { sw.isEnabled = false; bioRow.alpha = 0.5f }
        bioRow.contentDescription = a.t("Déverrouiller avec la biométrie", "Unlock with Biometrics")
        addView(ui.inset(ui.card(bioRow)))
        addView(ui.footnote(if (avail == me.somalabs.onepass.vault.BiometricUnlock.Availability.AVAILABLE)
            a.t("La clé reste dans le Keystore Android. Le mot de passe maître est redemandé tous les 14 jours, après un redémarrage et quand les empreintes ou le visage enregistrés changent.",
                "The key stays in the Android Keystore. Your master password is asked for again every 14 days, after a restart and when the enrolled fingerprints or face change.")
        else a.t("La biométrie n'est pas configurée sur cet appareil. Le mot de passe maître déverrouille OnePass.", "Biometrics aren't set up on this device. Your master password unlocks OnePass.")))
        a.background({ a.vault.protection }) { r ->
            info.text = a.t("Les clés de cet appareil sont scellées par ", "This device's keys are sealed by ") + r.getOrDefault("Android Keystore") +
                a.t(". Les captures d'écran sont bloquées dans OnePass.", ". Screenshots are blocked in OnePass.") +
                if (a.debuggable) a.t(" (Build de test : captures autorisées.)", " (Test build: screenshots allowed.)") else ""
        }
        addView(ui.sectionHeader(a.t("Presse-papiers", "Clipboard")))
        addView(ui.inset(ui.card(ui.row(title = a.t("Effacer après", "Clear After"), value = "90 s", chevron = false))))
        addView(ui.footnote(a.t("Un secret copié est marqué sensible et effacé s'il est toujours dans le presse-papiers.", "A copied secret is marked sensitive and cleared if it is still on the clipboard.")))
    }

    /** "Activer la biométrie": the master password, then one fingerprint or face check. */
    private fun enableBiometrics(sw: android.widget.Switch) {
        val bio = a.vault.biometrics
        val pw = ui.field(a.t("Mot de passe maître", "Master Password"), password = true)
        val err = ui.footnote("", ui.red)
        var proceeding = false
        val d = a.sheet(a.t("Activer la biométrie", "Turn On Biometrics"), a.t("Annuler", "Cancel"), a.t("Activer", "Turn On") to { d ->
            val chars = pw.text.toString().toCharArray()
            if (chars.isEmpty()) return@to
            pw.text.clear()
            err.text = ""
            a.background({ a.vault.accountUnlockKey(chars) }) { r ->
                chars.fill(' ')
                r.onSuccess { auk ->
                    proceeding = true
                    d.dismiss()
                    bio.enroll(a, a.t("Activer la biométrie", "Turn On Biometrics"), a.t("Confirme pour déverrouiller OnePass ainsi.", "Confirm to unlock OnePass this way."), a.t("Annuler", "Cancel"), auk) { ok, e ->
                        sw.isChecked = ok
                        if (ok) a.toast(a.t("La prochaine fois, la biométrie suffit pour ouvrir OnePass.", "Next time, biometrics are all it takes to open OnePass."))
                        else if (e != null) a.toast(e.toString())
                    }
                }.onFailure { err.text = if (it is me.somalabs.onepass.core.OnePassException.WrongPassword) a.t("Mot de passe incorrect.", "Incorrect password.") else a.message(it) }
            }
        }) { _ ->
            LinearLayout(a).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(0, ui.dp(8), 0, ui.dp(40))
                addView(ui.footnote(a.t("Saisis ton mot de passe maître, puis confirme avec la biométrie.", "Enter your master password, then confirm with biometrics.")))
                addView(ui.inset(ui.card(pw), top = Ios.Space.S))
                addView(err)
            }
        }
        d.setOnDismissListener { if (!proceeding && !bio.enrolled) sw.isChecked = false }
        pw.requestFocus()
    }

    private fun changePassword() {
        val current = ui.field(a.t("Mot de passe actuel", "Current Password"), password = true)
        val new1 = ui.field(a.t("Nouveau mot de passe", "New Password"), password = true)
        val new2 = ui.field(a.t("Confirme le nouveau", "Confirm New Password"), password = true)
        val err = ui.footnote("", ui.red)
        a.sheet(a.t("Mot de passe maître", "Master Password"), a.t("Annuler", "Cancel"), a.t("Changer", "Change") to { d ->
            val n = new1.text.toString()
            when {
                n != new2.text.toString() -> err.text = a.t("Les deux saisies doivent être identiques.", "Both entries must match.")
                me.somalabs.onepass.core.passwordStrengthBits(n) < MASTER_MIN_BITS || n.length < MASTER_MIN_LENGTH -> err.text = a.t("Pas encore assez solide : ajoute un mot, ou touche Générer.", "Not strong enough yet. Add a word, or tap Generate.")
                else -> {
                    val cur = current.text.toString().toCharArray()
                    val nw = n.toCharArray()
                    err.text = ""
                    a.background({ a.vault.changePassword(cur, nw) }) { r ->
                        cur.fill(' '); nw.fill(' ')
                        r.onSuccess { d.dismiss(); a.toast(a.t("Mot de passe maître changé", "Master password changed")) }
                            .onFailure { err.text = a.message(it) }
                    }
                }
            }
        }) { _ ->
            LinearLayout(a).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(0, ui.dp(8), 0, ui.dp(40))
                addView(ui.inset(ui.card(current)))
                addView(ui.inset(ui.card(new1, new2), top = Ios.Space.XL))
                addView(ui.footnote(a.t("Ta Secret Key ne change pas. Tes autres appareils te demanderont le nouveau mot de passe.", "Your Secret Key does not change. Your other devices will ask for the new password.")))
                addView(err)
            }
        }
    }

    // ---- Comptes --------------------------------------------------------------------------------------

    private fun accounts(): View = a.pushedPage(a.t("Comptes", "Accounts"), largeTitle = true) {
        val name = ui.field(a.t("Ton prénom", "Your first name"), a.profileName)
        addView(ui.capsLabel(a.t("Profil", "Profile")))
        addView(ui.inset(ui.card(name)))
        addView(a.link(a.t("Enregistrer le nom", "Save Name")) {
            val n = name.text.toString().trim()
            val s = a.session() ?: return@link
            a.background({ s.setProfile(n, ByteArray(0)) }) { r -> r.onFailure { a.toast(a.message(it)) }; a.reload() }
        })
        val s = a.vault.session
        val id = runCatching { s?.accountId() }.getOrNull().orEmpty()
        addView(ui.capsLabel(a.t("Compte OnePass", "OnePass Account")))
        addView(ui.inset(ui.card(ui.row(title = a.t("Identifiant", "ID"), subtitle = id, chevron = false) { a.copy(id, false) })))
        addView(ui.footnote(a.t("Cet identifiant est imprimé sur ton Emergency Kit.", "This ID is printed on your Emergency Kit.")))
    }

    // ---- Coffres ----------------------------------------------------------------------------------------

    private fun vaults(): View = a.pushedPage(a.t("Coffres", "Vaults"), largeTitle = true) {
        val rows = a.vaults.sortedBy { it.meta.name.lowercase() }.map { v ->
            ui.row(icon = ui.monogram(v.meta.name.take(1).uppercase(), Ios.vaultColor(v.meta.color), 30, square = true), title = v.meta.name,
                subtitle = a.countLabel(v.itemCount.toInt())) { vaultEditor(v) }
        } + ui.row(icon = ui.glyph(R.drawable.ic_add, ui.accent, 24).apply { layoutParams = LinearLayout.LayoutParams(ui.dp(30), ui.dp(24)) },
            title = a.t("Nouveau coffre", "New Vault"), titleColor = ui.readableAccent, chevron = false) { vaultEditor(null) }
        addView(ui.inset(ui.card(*rows.toTypedArray()), top = Ios.Space.S))
    }

    /** New or edit a vault: name and color; delete when it is empty and not the last one. */
    fun vaultEditor(v: FfiVault?) {
        val name = ui.field(a.t("Nom du coffre", "Vault Name"), v?.meta?.name ?: "")
        var color = v?.meta?.color ?: "blue"
        val swatches = LinearLayout(a).apply { gravity = Gravity.CENTER; setPadding(ui.dp(8), ui.dp(14), ui.dp(8), ui.dp(14)) }
        fun draw() {
            swatches.removeAllViews()
            Ios.VAULT_COLORS.forEach { (key, c) ->
                swatches.addView(View(a).apply {
                    background = android.graphics.drawable.GradientDrawable().apply {
                        shape = android.graphics.drawable.GradientDrawable.OVAL
                        setColor(c)
                        if (key == color) setStroke(ui.dp(3), ui.label)
                    }
                    contentDescription = key
                    isClickable = true
                    setOnClickListener { color = key; draw() }
                }, LinearLayout.LayoutParams(0, ui.dp(30), 1f).apply { setMargins(ui.dp(4), 0, ui.dp(4), 0) })
            }
        }
        draw()
        val err = ui.footnote("", ui.red)
        a.sheet(if (v == null) a.t("Nouveau coffre", "New Vault") else v.meta.name, a.t("Annuler", "Cancel"), a.t("Enregistrer", "Save") to { d ->
            val n = name.text.toString().trim()
            if (n.isEmpty()) { err.text = a.t("Donne un nom au coffre.", "Give the vault a name."); return@to }
            val s = a.session() ?: return@to
            a.background({
                if (v == null) s.createVault(FfiVaultMeta(n, "lock", color, false, false))
                else s.updateVault(v.id, v.meta.copy(name = n, color = color))
            }) { r ->
                r.onSuccess { d.dismiss(); a.changed() }.onFailure { err.text = a.message(it) }
            }
        }) { d ->
            LinearLayout(a).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(0, ui.dp(8), 0, ui.dp(40))
                addView(ui.inset(ui.card(name)))
                addView(ui.capsLabel(a.t("Couleur", "Color")))
                addView(ui.inset(ui.card(swatches)))
                // "Partage" (sharing spec 10): the members, or "Partager ce coffre".
                if (v != null) {
                    addView(ui.capsLabel(a.t("Partage", "Sharing")))
                    addView(ui.inset(a.sharingScreens.vaultSection(v.id) { d.dismiss() }))
                }
                addView(err)
                if (v != null && a.vaults.size > 1) {
                    addView(ui.inset(ui.card(ui.row(title = a.t("Supprimer le coffre", "Delete Vault"), titleColor = ui.red, chevron = false) {
                        if (v.itemCount > 0u) {
                            err.text = a.t("Déplace ou supprime d'abord ses éléments.", "Move or delete its items first.")
                        } else a.confirm(a.t("Supprimer le coffre « ${v.meta.name} » ?", "Delete the vault “${v.meta.name}”?"), a.t("Supprimer", "Delete")) {
                            val s = a.session() ?: return@confirm
                            a.background({ s.deleteVault(v.id) }) { r -> r.onSuccess { d.dismiss(); a.changed() }.onFailure { err.text = a.message(it) } }
                        }
                    }), top = Ios.Space.XL))
                }
            }
        }
    }

    // ---- À propos -----------------------------------------------------------------------------------------

    private fun about(): View = a.pushedPage(a.t("À propos", "About"), largeTitle = true) {
        val head = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL; gravity = Gravity.CENTER_HORIZONTAL; setPadding(0, ui.dp(8), 0, ui.dp(8)) }
        head.addView(a.itemIconArt(R.mipmap.ic_launcher, 80))
        head.addView(ui.text("OnePass", 22f, ui.label, 700).apply { setPadding(0, ui.dp(12), 0, ui.dp(2)) })
        head.addView(ui.text("Version " + runCatching { a.packageManager.getPackageInfo(a.packageName, 0).let { "${it.versionName} (${it.longVersionCode})" } }.getOrDefault(""), 15f, ui.secondary))
        addView(head)
        addView(ui.inset(ui.card(
            ui.row(title = a.t("Licence", "License"), value = "AGPL-3.0", chevron = false),
            ui.row(title = a.t("Code source", "Source Code")) { runCatching { a.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/soma-intelligence/onepass"))) } },
            ui.row(title = a.t("Icônes de l'interface", "Interface Icons"), subtitle = "Material Symbols, Apache-2.0", chevron = false),
        ), top = Ios.Space.L))
        addView(ui.footnote(a.t("Chiffré de bout en bout. Ton coffre ne quitte pas cet appareil sans ton mot de passe maître et ta Secret Key.",
            "End-to-end encrypted. Your vault never leaves this device without your master password and Secret Key.")))
    }

}

/** A drawn tile (category, settings page, app icon) clipped to the iOS squircle radius. */
fun MainActivity.itemIconArt(res: Int, sizeDp: Int): View = ui.image(res, sizeDp).apply {
    outlineProvider = object : android.view.ViewOutlineProvider() {
        override fun getOutline(view: View, outline: android.graphics.Outline) = outline.setRoundRect(0, 0, view.width, view.height, ui.dp(sizeDp * 0.225f).toFloat())
    }
    clipToOutline = true
}
