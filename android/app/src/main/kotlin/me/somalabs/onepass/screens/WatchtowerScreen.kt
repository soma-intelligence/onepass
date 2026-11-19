package me.somalabs.onepass.screens

import android.content.Context
import android.content.Intent
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RectF
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.LinearLayout
import kotlin.math.cos
import kotlin.math.sin
import me.somalabs.onepass.MainActivity
import me.somalabs.onepass.R
import me.somalabs.onepass.core.FfiPwnedStatus
import me.somalabs.onepass.core.FfiWatchtowerOptions
import me.somalabs.onepass.core.FfiWatchtowerReport
import android.graphics.drawable.GradientDrawable
import me.somalabs.onepass.ui.Ios
import me.somalabs.onepass.ui.RxArt
import me.somalabs.onepass.ui.backdropPage
import me.somalabs.onepass.ui.disc
import me.somalabs.onepass.ui.rxCard
import me.somalabs.onepass.ui.rxCardHeader
import me.somalabs.onepass.ui.rxRow

/**
 * Watchtower as on iPhone (WatchtowerTab): the score dial with "Partager mon
 * score", one paragraph and the analyzed count, the password strength bar,
 * one full-colour card per check that flagged items ("Voir les éléments"),
 * then the checks with nothing to report in one card. All from the core's
 * report (`watchtowerReport`), computed off the main thread.
 */
class WatchtowerScreen(private val a: MainActivity) {
    private val ui get() = a.ui

    private enum class Source { LOCAL, BREACHES, SITES, BREACH_CATALOG }

    private class Card(val id: String, val checks: List<String>, val fr: String, val en: String, val msgFr: String, val msgEn: String, val icon: Int, val color: (Ios) -> Int, val source: Source)

    private val cards = listOf(
        Card("compromised", listOf("compromised"), "Mots de passe compromis", "Compromised Passwords",
            "Ils apparaissent dans des fuites de données connues. Change-les en priorité.", "They appear in known data breaches. Change them first.",
            R.drawable.ic_compromised, { it.red }, Source.BREACHES),
        Card("breached_site", listOf("breached_site"), "Sites piratés", "Breached sites",
            "Ces sites ont subi une fuite depuis ton dernier changement de mot de passe. Change-le sur chacun.", "These sites had a breach since you last changed your password. Change it on each one.",
            R.drawable.ic_breached, { it.red }, Source.BREACH_CATALOG),
        Card("provider_exposed", listOf("provider_exposed"), "Comptes de connexion exposés", "Exposed sign-in accounts",
            "Un compte qui te sert à te connecter ailleurs est compromis, faible, réutilisé ou sans double authentification : tous les sites qui en dépendent sont exposés.", "An account you use to sign in elsewhere is compromised, weak, reused or without two-factor authentication: every site that depends on it is exposed.",
            R.drawable.ic_exposed, { it.red }, Source.LOCAL),
        Card("reused", listOf("reused"), "Mots de passe réutilisés", "Reused Passwords",
            "Un même mot de passe sur plusieurs comptes : une seule fuite suffit à tous les ouvrir.", "One password on several accounts: a single breach opens them all.",
            R.drawable.ic_reused, { it.orange }, Source.LOCAL),
        Card("weak", listOf("weak"), "Mots de passe faibles", "Weak Passwords",
            "Faciles à deviner. Remplace-les par des mots de passe générés.", "Easy to guess. Replace them with generated passwords.",
            R.drawable.ic_lock_open, { it.orange }, Source.LOCAL),
        Card("passkey", listOf("passkey_available"), "Passkeys disponibles", "Passkeys Available",
            "Ces sites acceptent les passkeys, plus sûres et plus simples qu'un mot de passe.", "These sites support passkeys, safer and simpler than a password.",
            R.drawable.ic_passkey, { it.accent }, Source.SITES),
        Card("2fa", listOf("missing_2fa"), "Double authentification disponible", "Two-factor authentication available",
            "Ces sites proposent des codes à usage unique que tu n'as pas encore ajoutés.", "These sites offer one-time codes you haven’t added yet.",
            R.drawable.ic_two_factor, { it.blue }, Source.SITES),
        Card("http", listOf("insecure_url"), "Sites en HTTP", "HTTP Sites",
            "Ces adresses ne sont pas chiffrées. Passe-les en HTTPS si le site le permet.", "These addresses aren’t encrypted. Switch them to HTTPS if the site allows it.",
            R.drawable.ic_globe, { it.yellow }, Source.LOCAL),
        Card("expiring", listOf("expired", "expiring"), "Éléments qui expirent", "Expiring Items",
            "Cartes, documents et licences expirés ou qui expirent dans les 30 jours.", "Cards, documents and licenses that expired or expire within 30 days.",
            R.drawable.ic_calendar_alert, { Color.rgb(0xFF, 0x2D, 0x55) }, Source.LOCAL),
        Card("wifi", listOf("wifi_insecure"), "Wi-Fi peu protégés", "Poorly protected Wi-Fi",
            "Ces réseaux utilisent WEP ou aucun chiffrement. Passe-les en WPA2 ou WPA3 sur le routeur.", "These networks use WEP or no encryption. Switch them to WPA2 or WPA3 on the router.",
            R.drawable.ic_wifi, { it.orange }, Source.LOCAL),
        Card("ssh", listOf("ssh_weak"), "Clés SSH faibles", "Weak SSH keys",
            "Clés RSA de moins de 3 072 bits ou DSA. Remplace-les par une clé Ed25519.", "RSA keys under 3,072 bits, or DSA. Replace them with an Ed25519 key.",
            R.drawable.ic_terminal, { it.orange }, Source.LOCAL),
        Card("wallet", listOf("wallet_no_backup"), "Portefeuilles sans sauvegarde", "Wallets without a backup",
            "Indique où est rangée la copie physique de la phrase de récupération de ces portefeuilles.", "Note where the physical copy of these wallets' recovery phrase is kept.",
            R.drawable.ic_archive, { it.yellow }, Source.LOCAL),
        Card("duplicate", listOf("duplicate"), "Doublons", "Duplicates",
            "Même site et même identifiant dans plusieurs éléments. Garde-en un seul.", "Same site and same username in several items. Keep only one.",
            R.drawable.ic_duplicates, { Color.rgb(0x8E, 0x8E, 0x93) }, Source.LOCAL),
        Card("old", listOf("old_password"), "Vieux mots de passe", "Old Passwords",
            "Inchangés depuis plus d'un an. Pense à les renouveler.", "Unchanged for over a year. Consider renewing them.",
            R.drawable.ic_history, { Color.rgb(0x8E, 0x8E, 0x93) }, Source.LOCAL),
        Card("pending", listOf("pending_unused"), "Mot de passe en attente", "Pending password",
            "Mot de passe généré mais jamais confirmé depuis plus de 30 jours. L'inscription n'a sans doute pas abouti.", "Generated password never confirmed for over 30 days. The signup probably did not finish.",
            R.drawable.ic_hourglass, { Color.rgb(0x8E, 0x8E, 0x93) }, Source.LOCAL),
    )

    private fun Card.title() = a.t(fr, en)
    private fun Card.ids(r: FfiWatchtowerReport) = r.checks.filter { it.check in checks }.flatMap { it.itemIds }.toSet()
    private fun Card.alert() = id in setOf("compromised", "expiring", "breached_site", "provider_exposed")

    /** Why a card has no figure: its source did not run (no network check on Android yet). */
    private fun Card.unavailable(r: FfiWatchtowerReport): String? = when (source) {
        Source.LOCAL -> null
        Source.BREACHES -> when (r.pwned) {
            is FfiPwnedStatus.Checked, is FfiPwnedStatus.Partial -> null
            is FfiPwnedStatus.Unavailable -> if (checking) a.t("Vérification des fuites…", "Checking for breaches…") else a.t("Fuites non vérifiées (pas de réseau).", "Breaches not checked (no network).")
            is FfiPwnedStatus.Disabled -> a.t("Vérification des fuites désactivée.", "Breach check turned off.")
        }
        Source.SITES -> if (r.sitesChecked) null else a.t("Catalogue des sites indisponible.", "Site catalog unavailable.")
        Source.BREACH_CATALOG -> if (!a.watchFetcher.checkBreaches) a.t("Active « Vérifier les fuites » pour télécharger le catalogue des sites piratés.", "Turn on “Check for breaches” to download the list of breached sites.")
            else if (checking) a.t("Vérification des fuites…", "Checking for breaches…") else null
    }

    /** Computes the report if needed, then redraws (when still on Watchtower or Home). */
    private var computing = false

    /** "Vérification des fuites" while the ranges download. */
    private var checking = false

    /**
     * Two passes as on iPhone: offline first (local checks, the catalogs on disk,
     * the SHA-1 prefixes to fetch), then, with "Vérifier les fuites" on, the HIBP
     * ranges and the catalogs are downloaded on their own thread and the report
     * computed again.
     */
    fun ensureReport() {
        if (a.report != null || computing) return
        val s = a.vault.session ?: return
        computing = true
        val fetcher = a.watchFetcher
        val breaches = fetcher.checkBreaches
        fun options(ranges: List<me.somalabs.onepass.core.FfiRangeResponse>?, d: me.somalabs.onepass.vault.WatchtowerFetcher.Directories) =
            FfiWatchtowerOptions(30u, 365u, ranges, emptyList(), d.breaches, d.sitePack)
        a.background({ s.watchtowerReport(options(if (breaches) emptyList() else null, fetcher.directories(false))) }) { r ->
            r.onFailure { computing = false; a.toast(a.message(it)) }
            val first = r.getOrNull() ?: return@background
            a.report = first
            if (!breaches) { computing = false; a.renderIfRoot(); return@background }
            checking = true
            a.renderIfRoot()
            Thread {
                val second = runCatching {
                    val dirs = fetcher.directories(true)
                    val ranges = fetcher.ranges(first.missingPrefixes)
                    if (a.vault.session !== s) null else s.watchtowerReport(options(ranges, dirs))
                }.getOrNull()
                a.main.post {
                    computing = false
                    checking = false
                    if (second != null && a.report === first && a.vault.session === s) a.report = second
                    a.renderIfRoot()
                }
            }.start()
        }
    }

    private fun pwnedText(r: FfiWatchtowerReport): String = if (checking) a.t(" · vérification des fuites…", " · checking for breaches…") else when (val p = r.pwned) {
        is FfiPwnedStatus.Checked -> a.t(" · fuites vérifiées", " · breaches checked")
        is FfiPwnedStatus.Partial -> a.t(" · fuites vérifiées en partie (${p.failedPrefixes} requêtes en échec)", " · breaches partly checked (${p.failedPrefixes} requests failed)")
        is FfiPwnedStatus.Unavailable -> a.t(" · fuites non vérifiées (pas de réseau)", " · breaches not checked (no network)")
        is FfiPwnedStatus.Disabled -> a.t(" · vérification des fuites désactivée", " · breach check turned off")
    }

    /** "Vérifier les fuites" at the bottom of Watchtower, with what is sent. */
    private fun breachSetting(): View {
        val f = a.watchFetcher
        val row = ui.toggleRow(a.t("Vérifier les fuites", "Check for Breaches"), a.t("Tes mots de passe ne quittent jamais l'appareil.", "Your passwords never leave this device."), f.checkBreaches) { on ->
            f.checkBreaches = on
            a.report = null
            a.renderIfRoot()
        }
        row.addView(a.barIcon(R.drawable.ic_info, a.t("Ce qui est envoyé", "What is sent")) {
            android.app.AlertDialog.Builder(a).setTitle(a.t("Ce qui est envoyé", "What is sent"))
                .setMessage(a.t("Pour chaque mot de passe, OnePass envoie à Have I Been Pwned les 5 premiers caractères de son empreinte SHA-1, partagés avec des centaines d'autres, et compare le reste ici. La liste des sites piratés est téléchargée en entier et gardée une semaine ; les vérifications 2FA et passkeys lisent le catalogue des sites livré avec l'app. Désactivé, aucune requête réseau.",
                    "For each password, OnePass sends Have I Been Pwned the first 5 characters of its SHA-1 hash, shared with hundreds of others, and compares the rest here. The list of breached sites is downloaded whole and kept for a week; the 2FA and passkey checks read the site catalog shipped with the app. When off, no network request."))
                .setPositiveButton("OK", null).show()
        }, row.childCount - 1)
        return ui.card(row)
    }

    /**
     * Watchtower in the RX look (RXWatchtower): the art fading into the page, the title with the
     * glass shield, the dial, a red card per alert, the three stat tiles (weak, reused, 2FA),
     * Améliorer for the other findings, then the strength bar, the clear checks and the setting.
     */
    fun screen(): View {
        val report = a.report
        if (report == null) ensureReport()
        val score = report?.score?.toInt()
        return a.backdropPage(RxArt.watchtower, null) {
            addView(LinearLayout(a).apply {
                gravity = Gravity.CENTER_VERTICAL
                setPadding(ui.dp(16), ui.dp(8), ui.dp(16), 0)
                addView(a.accountButton())
                addView(View(a), LinearLayout.LayoutParams(0, 1, 1f))
                if (score != null) addView(ui.roundButton(R.drawable.ic_share, a.t("Partager mon score", "Share My Score")) {
                    val text = a.t("Mon score de sécurité OnePass : $score sur 100.", "My OnePass security score: $score out of 100.")
                    a.startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, text), null))
                }.apply { (getChildAt(0) as android.widget.ImageView).imageTintList = android.content.res.ColorStateList.valueOf(ui.label) })
            })
            val head = LinearLayout(a).apply { gravity = Gravity.CENTER_VERTICAL; setPadding(ui.dp(20), ui.dp(12), ui.dp(12), 0) }
            val names = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL }
            names.addView(ui.text("Watchtower", 34f, ui.label, 700))
            names.addView(ui.text(a.t("Score de sécurité", "Security Score"), 17f, ui.secondary).apply { setPadding(0, ui.dp(6), 0, 0) })
            head.addView(names, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            head.addView(ui.image(R.drawable.rx_watch_shield, 112).apply { importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO })
            addView(head)
            addView(ScoreDial(a, ui, score), LinearLayout.LayoutParams(ui.dp(260), ui.dp(260)).apply { gravity = Gravity.CENTER_HORIZONTAL; topMargin = ui.dp(8) })
            if (report == null) {
                addView(ui.text(a.t("Analyse…", "Analyzing…"), 15f, ui.tertiary).apply { gravity = Gravity.CENTER; setPadding(ui.dp(20), 0, ui.dp(20), 0) })
                return@backdropPage
            }
            val n = report.itemsAnalyzed.toInt()
            addView(ui.text((if (n == 1) a.t("1 élément analysé", "1 item analyzed") else a.t("$n éléments analysés", "$n items analyzed")) + pwnedText(report), 15f, ui.tertiary).apply {
                gravity = Gravity.CENTER; setPadding(ui.dp(24), 0, ui.dp(24), ui.dp(20))
            })
            val flagged = cards.filter { it.ids(report).isNotEmpty() }
            flagged.filter { it.alert() }.forEach { addView(ui.inset(alertCard(it, report), bottom = Ios.Space.L)) }
            addView(statTiles(report))
            val stats = setOf("weak", "reused", "2fa")
            val improve = flagged.filter { !it.alert() && it.id !in stats }
            if (improve.isNotEmpty()) addView(ui.rxCard {
                addView(ui.rxCardHeader(a.t("Améliorer", "Improve")))
                improve.forEach { c ->
                    addView(ui.rxRow(ui.disc(c.icon, c.color(ui), 40), c.title(), a.t(c.msgFr, c.msgEn), c.ids(report).size.toString(), chevron = true) { open(c, report) })
                }
            })
            if (flagged.none { it.alert() }) addView(ui.rxCard {
                addView(ui.rxRow(ui.disc(R.drawable.ic_shield_check, ui.green, 40), a.t("Aucun problème", "No Issues"), a.t("Aucun mot de passe exposé ou compromis.", "No exposed or compromised passwords.")))
            })
            addView(ui.inset(strength(report.strength.map { it.toInt() }), bottom = Ios.Space.L))
            val clear = cards.filter { it.ids(report).isEmpty() }
            if (clear.isNotEmpty()) addView(ui.inset(clearCard(clear, report), bottom = Ios.Space.L))
            addView(ui.inset(breachSetting()))
        }
    }

    private fun open(c: Card, r: FfiWatchtowerReport) {
        val ids = c.ids(r)
        if (c.id == "duplicate") a.duplicates.open() else a.push { flaggedItems(c.title(), ids) }
    }

    /** An alert (compromised, breached site, exposed account, expiring) as a red card. */
    private fun alertCard(c: Card, r: FfiWatchtowerReport): View {
        val count = c.ids(r).size
        val row = LinearLayout(a).apply {
            gravity = Gravity.CENTER_VERTICAL
            background = ui.pressable(GradientDrawable(GradientDrawable.Orientation.TOP_BOTTOM, intArrayOf(Color.rgb(0xEE, 0x5C, 0x5C), Color.rgb(0xD9, 0x3A, 0x40))).apply {
                cornerRadius = ui.dp(Ios.Radius.CARD).toFloat()
            }, Ios.Radius.CARD)
            elevation = ui.dp(6).toFloat()
            setPadding(ui.dp(20), ui.dp(18), ui.dp(14), ui.dp(18))
            isClickable = true
            contentDescription = "$count, " + c.title()
            setOnClickListener { open(c, r) }
        }
        val badge = android.widget.FrameLayout(a).apply {
            background = GradientDrawable().apply { shape = GradientDrawable.OVAL; setColor(Color.WHITE) }
            addView(ui.text("!", 26f, Color.rgb(0xD9, 0x3A, 0x40), 800).apply { gravity = Gravity.CENTER }, android.widget.FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        }
        row.addView(badge, LinearLayout.LayoutParams(ui.dp(48), ui.dp(48)).apply { marginEnd = ui.dp(16) })
        val texts = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL }
        texts.addView(ui.text("$count · " + c.title(), 20f, Color.WHITE, 700))
        texts.addView(ui.text(a.t(c.msgFr, c.msgEn), 15f, Color.argb(0xE6, 255, 255, 255)).apply { setPadding(0, ui.dp(4), 0, 0) })
        row.addView(texts, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        row.addView(ui.glyph(R.drawable.ic_chevron_right, Color.WHITE, 20))
        return row
    }

    /** Faibles, Réutilisés, 2FA disponible: three tiles, the figure under a coloured disc. */
    private fun statTiles(r: FfiWatchtowerReport): View {
        val row = LinearLayout(a).apply { setPadding(ui.dp(16), 0, ui.dp(16), ui.dp(Ios.Space.L)) }
        listOf(
            Triple("weak", a.t("Faibles", "Weak"), ui.orange),
            Triple("reused", a.t("Réutilisés", "Reused"), ui.purple),
            Triple("2fa", a.t("2FA disponible", "2FA Available"), ui.teal),
        ).forEachIndexed { i, (id, label, color) ->
            val c = cards.first { it.id == id }
            val count = c.ids(r).size
            val unavailable = c.unavailable(r) != null
            val tile = LinearLayout(a).apply {
                orientation = LinearLayout.VERTICAL
                background = ui.pressable(ui.rounded(ui.card, Ios.Radius.CARD), Ios.Radius.CARD)
                setPadding(ui.dp(14), ui.dp(14), ui.dp(10), ui.dp(16))
                contentDescription = "$label: " + if (unavailable) "–" else count.toString()
                if (count > 0) { isClickable = true; setOnClickListener { open(c, r) } }
            }
            tile.addView(ui.disc(c.icon, color, 36))
            tile.addView(ui.text(if (unavailable) "–" else count.toString(), 28f, ui.label, 700).apply { fontFeatureSettings = "tnum"; setPadding(0, ui.dp(12), 0, ui.dp(4)) })
            tile.addView(ui.text(label, 15f, ui.secondary).apply { maxLines = 2 })
            row.addView(tile, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.MATCH_PARENT, 1f).apply { if (i > 0) marginStart = ui.dp(10) })
        }
        return row
    }

    private fun strength(levels: List<Int>): View {
        val total = levels.sum()
        val col = LinearLayout(a).apply {
            orientation = LinearLayout.VERTICAL
            background = ui.rounded(ui.card, Ios.Radius.CARD)
            setPadding(ui.dp(20), ui.dp(18), ui.dp(20), ui.dp(18))
        }
        val head = LinearLayout(a).apply { gravity = Gravity.CENTER_VERTICAL }
        head.addView(ui.text(a.t("Force des mots de passe", "Password Strength"), 22f, ui.label, 600), LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        head.addView(ui.text(if (total == 1) a.t("1 mot de passe", "1 password") else a.t("$total mots de passe", "$total passwords"), 15f, ui.secondary))
        col.addView(head)
        if (total == 0) {
            col.addView(ui.text(a.t("Aucun mot de passe à analyser pour l'instant.", "No passwords to analyze yet."), 15f, ui.secondary).apply { setPadding(0, ui.dp(12), 0, 0) })
            return col
        }
        val colors = listOf(ui.red, ui.orange, ui.yellow, Color.rgb(0x00, 0xC7, 0xBE), ui.green)
        val names = listOf(a.t("Trop courts", "Too short"), a.t("Faibles", "Weak"), a.t("Moyens", "Fair"), a.t("Bons", "Good"), a.t("Excellents", "Excellent"))
        val bar = LinearLayout(a).apply { clipToOutline = true; background = ui.rounded(ui.fill, 6) }
        levels.forEachIndexed { i, n ->
            if (n > 0) bar.addView(View(a).apply { setBackgroundColor(colors[i]) }, LinearLayout.LayoutParams(0, ui.dp(14), n.toFloat()).apply { marginEnd = ui.dp(3) })
        }
        col.addView(bar, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ui.dp(14)).apply { topMargin = ui.dp(14) })
        val legend = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL; setPadding(0, ui.dp(12), 0, 0) }
        levels.forEachIndexed { i, n ->
            if (n == 0) return@forEachIndexed
            val line = LinearLayout(a).apply { gravity = Gravity.CENTER_VERTICAL; setPadding(0, ui.dp(3), 0, ui.dp(3)) }
            line.addView(View(a).apply { background = ui.rounded(colors[i], 4) }, LinearLayout.LayoutParams(ui.dp(10), ui.dp(10)).apply { marginEnd = ui.dp(8) })
            line.addView(ui.text(names[i], 15f, ui.label), LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            line.addView(ui.text(n.toString(), 15f, ui.secondary))
            legend.addView(line)
        }
        col.addView(legend)
        return col
    }

    private fun clearCard(list: List<Card>, r: FfiWatchtowerReport): View {
        val col = LinearLayout(a).apply {
            orientation = LinearLayout.VERTICAL
            background = ui.rounded(ui.card, Ios.Radius.CARD)
            setPadding(0, 0, 0, ui.dp(8))
        }
        col.addView(ui.text(a.t("Rien à signaler", "Nothing to Report"), 22f, ui.label, 600).apply { setPadding(ui.dp(20), ui.dp(18), ui.dp(16), ui.dp(8)) })
        list.forEachIndexed { i, c ->
            if (i > 0) col.addView(ui.separatorLine(20 + 30 + 12))
            val note = c.unavailable(r)
            val row = LinearLayout(a).apply { gravity = Gravity.CENTER_VERTICAL; setPadding(ui.dp(20), ui.dp(9), ui.dp(16), ui.dp(9)) }
            row.addView(ui.disc(c.icon, c.color(ui), 30).apply { (layoutParams as LinearLayout.LayoutParams).marginEnd = ui.dp(12) })
            val texts = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL }
            texts.addView(ui.text(c.title(), 15f, ui.label, 500))
            note?.let { texts.addView(ui.text(it, 12f, ui.secondary).apply { setPadding(0, ui.dp(2), 0, 0) }) }
            row.addView(texts, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            if (note == null) row.addView(ui.glyph(R.drawable.ic_check_circle, ui.green, 22))
            if (c.id == "duplicate") { row.background = ui.pressable(null); row.isClickable = true; row.setOnClickListener { a.duplicates.open() } }
            col.addView(row)
        }
        return col
    }

    private fun flaggedItems(title: String, ids: Set<String>): View = a.pushedPage(title, largeTitle = true) {
        val list = a.summaries.filter { it.id in ids && it.trashedAt == null }.sortedBy { it.title.lowercase() }
        addView(a.itemsCard(list, a.t("Aucun élément concerné pour l'instant.", "No item affected for now.")))
    }

    companion object {
        fun scoreColor(ui: Ios, score: Int) = when {
            score < 40 -> ui.red
            score < 60 -> ui.orange
            score < 80 -> ui.yellow
            else -> ui.green
        }

        fun scoreLabel(a: MainActivity, score: Int) = when {
            score < 40 -> a.t("Faible", "Weak")
            score < 60 -> a.t("Moyen", "Fair")
            score < 80 -> a.t("Bon", "Good")
            score < 95 -> a.t("Excellent", "Excellent")
            else -> a.t("Fantastique", "Fantastic")
        }
    }

    /** The three-quarter dial of PhoneScoreGauge: track, arc, ticks, figure and word. */
    private class ScoreDial(private val a: MainActivity, private val ui: Ios, private val score: Int?) : FrameLayout(a as Context) {
        private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.STROKE; strokeCap = Paint.Cap.ROUND }
        private val color = score?.let { scoreColor(ui, it) } ?: ui.secondary

        init {
            setWillNotDraw(false)
            contentDescription = a.t("Score de sécurité", "Security Score") + (score?.let { " $it/100, " + scoreLabel(a, it) } ?: "")
            val col = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL; gravity = Gravity.CENTER }
            col.addView(ui.text(score?.toString() ?: "–", 72f, ui.label, 700).apply { gravity = Gravity.CENTER; fontFeatureSettings = "tnum" })
            col.addView(ui.text((score?.let { scoreLabel(a, it) } ?: a.t("Analyse…", "Analyzing…")).uppercase(), 15f, if (score == null) ui.secondary else color, 600).apply { gravity = Gravity.CENTER })
            addView(col, LayoutParams(LayoutParams.WRAP_CONTENT, LayoutParams.WRAP_CONTENT, Gravity.CENTER).apply { topMargin = ui.dp(4) })
        }

        override fun onDraw(c: Canvas) {
            super.onDraw(c)
            val w = width.toFloat()
            val d = ui.dp(1).toFloat()
            val r = w / 2 - 10 * d
            val oval = RectF(w / 2 - r, w / 2 - r, w / 2 + r, w / 2 + r)
            val faint = if (ui.dark) Color.argb(26, 255, 255, 255) else Color.argb(26, 0, 0, 0)
            paint.strokeWidth = 18 * d
            paint.color = faint
            c.drawArc(oval, 135f, 270f, false, paint)
            val fraction = (score ?: 0) / 100f
            if (score != null && fraction > 0) {
                paint.color = color
                c.drawArc(oval, 135f, 270f * fraction, false, paint)
            }
            val ticks = 40
            val lit = if (score == null) -1 else Math.round(fraction * ticks)
            val outer = w / 2 - 30 * d
            val inner = outer - 9 * d
            paint.strokeWidth = 2 * d
            for (i in 0..ticks) {
                val ang = Math.toRadians(135.0 + 270.0 * i / ticks)
                paint.color = if (i <= lit) Color.argb(153, Color.red(color), Color.green(color), Color.blue(color)) else if (ui.dark) Color.argb(31, 255, 255, 255) else Color.argb(31, 0, 0, 0)
                c.drawLine(w / 2 + inner * cos(ang).toFloat(), w / 2 + inner * sin(ang).toFloat(), w / 2 + outer * cos(ang).toFloat(), w / 2 + outer * sin(ang).toFloat(), paint)
            }
        }
    }
}
