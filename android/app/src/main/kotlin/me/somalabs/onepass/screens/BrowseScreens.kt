package me.somalabs.onepass.screens

import android.content.Context
import android.graphics.Color
import android.graphics.Outline
import android.text.Editable
import android.text.TextWatcher
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.ViewOutlineProvider
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import me.somalabs.onepass.MainActivity
import me.somalabs.onepass.R
import me.somalabs.onepass.core.FfiItemSummary
import me.somalabs.onepass.core.FfiItemType
import me.somalabs.onepass.ui.Category
import me.somalabs.onepass.ui.Ios
import me.somalabs.onepass.ui.RxArt
import me.somalabs.onepass.ui.carousel
import me.somalabs.onepass.ui.favoriteTile
import me.somalabs.onepass.ui.glassChip
import me.somalabs.onepass.ui.heroPage
import me.somalabs.onepass.ui.quickAction
import me.somalabs.onepass.ui.quickActionRow
import me.somalabs.onepass.ui.rxCard
import me.somalabs.onepass.ui.rxCardHeader
import me.somalabs.onepass.ui.rxLink
import me.somalabs.onepass.ui.rxMessage
import me.somalabs.onepass.ui.rxRow

/**
 * The item's icon, rounded, with the favorite star badge (ItemIcon + favoriteBadge): the site's
 * brand from the icon pack when its web address (or, without one, its title) has one, else the
 * category artwork.
 */
fun MainActivity.itemIcon(type: FfiItemType, sizeDp: Int, favorite: Boolean = false, url: String? = null, title: String? = null): View {
    val box = FrameLayout(this).apply { layoutParams = LinearLayout.LayoutParams(ui.dp(sizeDp), ui.dp(sizeDp)) }
    val brand = siteIcon(type, url, title)
    // Large (the item hero, Favoris): the brand alone, as RX draws it; small: on its rounded tile.
    // A colour logo stays on its white tile in the dark appearance (a black mark would vanish).
    val bare = sizeDp >= 64 && (brand?.monochrome == true || !ui.dark)
    val art: View = if (brand != null) FrameLayout(this).apply {
        if (!bare) background = ui.rounded(if (brand.monochrome) ui.card else android.graphics.Color.WHITE, sizeDp * 0.225f, ui.hairline)
        val pad = ui.dp(sizeDp * (if (bare) 0.06f else 0.16f))
        addView(android.widget.ImageView(this@itemIcon).apply {
            setImageBitmap(brand.bitmap)
            scaleType = android.widget.ImageView.ScaleType.FIT_CENTER
            if (brand.monochrome) imageTintList = android.content.res.ColorStateList.valueOf(ui.label)
        }, FrameLayout.LayoutParams(ui.dp(sizeDp) - 2 * pad, ui.dp(sizeDp) - 2 * pad, Gravity.CENTER))
    } else ui.image(Category.of(type).art, sizeDp).apply {
        outlineProvider = object : ViewOutlineProvider() {
            override fun getOutline(view: View, outline: Outline) = outline.setRoundRect(0, 0, view.width, view.height, ui.dp(sizeDp * 0.225f).toFloat())
        }
        clipToOutline = true
    }
    box.addView(art, FrameLayout.LayoutParams(ui.dp(sizeDp), ui.dp(sizeDp)))
    if (favorite) {
        val badge = FrameLayout(this).apply {
            background = android.graphics.drawable.GradientDrawable().apply { shape = android.graphics.drawable.GradientDrawable.OVAL; setColor(ui.card) }
            addView(ui.glyph(R.drawable.ic_star_fill, ui.amberStar, 12), FrameLayout.LayoutParams(ui.dp(12), ui.dp(12), Gravity.CENTER))
        }
        // Large icons keep the badge inside their box (a parent clips what overflows).
        val b = if (sizeDp >= 64) (sizeDp * 0.3f).toInt() else 16
        (badge.getChildAt(0).layoutParams as FrameLayout.LayoutParams).apply { width = ui.dp(b * 0.75f); height = ui.dp(b * 0.75f) }
        box.addView(badge, FrameLayout.LayoutParams(ui.dp(b), ui.dp(b), Gravity.END or Gravity.BOTTOM).apply { if (sizeDp < 64) setMargins(0, 0, -ui.dp(3), -ui.dp(3)) })
        box.clipChildren = false
    }
    return box
}

/** The kinds that can carry a site's brand icon. */
/** The brand icon of an item from the icon pack: by web address, or by title for an item without one. */
fun siteIcon(type: FfiItemType, url: String?, title: String?): me.somalabs.onepass.ui.IconPack.Icon? {
    val pack = me.somalabs.onepass.ui.IconPack.shared
    return if (pack == null || type !in brandTypes) null else me.somalabs.onepass.ui.IconPack.host(url)?.let { pack.forHost(it) }
        ?: title?.takeIf { url.isNullOrBlank() }?.let { pack.forTitle(it) }
}

private val brandTypes = setOf(FfiItemType.LOGIN, FfiItemType.PASSWORD, FfiItemType.API_CREDENTIAL, FfiItemType.SUBSCRIPTION, FfiItemType.MEMBERSHIP, FfiItemType.REWARD_PROGRAM, FfiItemType.EMAIL)

/** The second line of a list row: the subtitle, or the category's name (ItemListRow). */
fun MainActivity.secondLine(s: FfiItemSummary): String =
    s.subtitle.ifBlank { s.signInProvider?.let { t("Se connecte avec ", "Signs in with ") + it.replaceFirstChar(Char::uppercase) } ?: Category.of(s.itemType).singular(this) }

fun MainActivity.itemRow(s: FfiItemSummary, vaultName: String? = null): View =
    ui.row(
        icon = itemIcon(s.itemType, 36, s.favorite, s.primaryUrl, s.title),
        title = s.title.ifBlank { t("Sans titre", "Untitled") },
        subtitle = listOfNotNull(secondLine(s), vaultName).joinToString(" · "),
        minHeightDp = 60,
    ) { items.detail(s.vaultId, s.id) }

fun MainActivity.countLabel(n: Int) = if (n == 1) t("1 élément", "1 item") else t("$n éléments", "$n items")

/** A list of items in one inset card, or an empty note. */
fun MainActivity.itemsCard(list: List<FfiItemSummary>, empty: String): View {
    if (list.isEmpty()) return ui.footnote(empty).apply { gravity = Gravity.CENTER; setPadding(ui.dp(32), ui.dp(48), ui.dp(32), ui.dp(24)) }
    val showVault = vaults.size > 1
    val names = vaults.associate { it.id to it.meta.name }
    val card = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        background = ui.rounded(ui.card, Ios.Radius.CARD, ui.hairline)
        clipToOutline = true
    }
    list.forEachIndexed { i, s ->
        card.addView(itemRow(s, if (showVault) names[s.vaultId] else null))
        if (i < list.lastIndex) card.addView(ui.separatorLine(64))
    }
    return ui.inset(card)
}


/**
 * Accueil, Éléments, the item lists and Recherche, as on iPhone (HomeTab,
 * ItemsTab, CategoryListView, SearchTab).
 */
class BrowseScreens(private val a: MainActivity) {
    private val ui get() = a.ui
    private val prefs by lazy { a.getSharedPreferences("browse", Context.MODE_PRIVATE) }

    // ---- Accueil ---------------------------------------------------------------------------------

    /**
     * Accueil in the RX look (RXHomePage): the photo hero (account menu, the security score in
     * words, three quick actions) that fades as the page sheet scrolls over it, then Récents,
     * Favoris as a carousel and Coffres.
     */
    fun home(): View {
        val first = a.profileName.split(" ").firstOrNull { it.isNotBlank() }
        val active = a.active
        val onPhoto = ui.dark
        val ink = if (onPhoto) Color.WHITE else ui.label
        // The sharing notices on top (iPhone `SharingBanners`): a recovery request, invitations, changed keys, received items.
        val banners = a.sharingScreens.banners()
        val score = a.report?.score?.toInt()
        return a.heroPage(RxArt.home(ui), darkPhoto = onPhoto, hero = {
            addView(LinearLayout(a).apply { addView(a.accountButton(onPhoto)) })
            // The score block: one button that opens Watchtower.
            val block = LinearLayout(a).apply {
                orientation = LinearLayout.VERTICAL
                gravity = Gravity.CENTER_HORIZONTAL
                isClickable = true
                setOnClickListener { a.selectTab(MainActivity.Tab.WATCHTOWER) }
                setPadding(0, ui.dp(56), 0, 0)
            }
            block.addView(ui.text(if (first == null) a.t("Bonjour", "Hi") else a.t("Bonjour $first", "Hi $first"), 15f, if (onPhoto) Color.argb(0xD9, 255, 255, 255) else ui.secondary, 500).apply { gravity = Gravity.CENTER; maxLines = 2 })
            val status = when {
                score == null -> a.t("Vérification…", "Checking…")
                score >= 80 -> a.t("Tout va bien", "All Good")
                score >= 60 -> a.t("Presque parfait", "Almost There")
                else -> a.t("À vérifier", "Needs a Look")
            }
            block.addView(ui.text(status, 44f, ink, 700).apply { gravity = Gravity.CENTER; maxLines = 2; setPadding(0, ui.dp(8), 0, ui.dp(12)) })
            val chip = ui.glassChip(ui.glyph(R.drawable.ic_shield_check, score?.let { WatchtowerScreen.scoreColor(ui, it) } ?: ui.green, 20), a.t("Score ", "Score ") + (score ?: 100), onPhoto)
            // The chip keeps its place while the score is computed: the hero does not jump.
            chip.visibility = if (score == null) View.INVISIBLE else View.VISIBLE
            block.addView(chip, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT))
            block.contentDescription = status + (score?.let { a.t(", score $it sur 100", ", score $it out of 100") } ?: "")
            addView(block, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
            addView(ui.quickActionRow(
                ui.quickAction(R.drawable.ic_add, a.t("Nouvel élément", "New Item"), onPhoto) { a.items.newItem(null) },
                ui.quickAction(R.drawable.ic_key, a.t("Générer", "Generate"), onPhoto) { a.items.generator(null) },
                ui.quickAction(R.drawable.ic_share, a.t("Partager", "Share"), onPhoto, enabled = score != null) {
                    val text = a.t("Mon score de sécurité OnePass : $score sur 100.", "My OnePass security score: $score out of 100.")
                    a.startActivity(android.content.Intent.createChooser(android.content.Intent(android.content.Intent.ACTION_SEND).setType("text/plain").putExtra(android.content.Intent.EXTRA_TEXT, text), null))
                },
            ), LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = ui.dp(40) })
        }) {
            banners?.let { addView(it) }
            if (active.isEmpty()) {
                addView(firstItemState())
                return@heroPage
            }
            addView(recentCard(active))
            addView(favoritesCard(active))
            addView(vaultsCard(active))
            active.filter { it.itemType == FfiItemType.IDENTITY }.minByOrNull { it.title.lowercase() }?.let { p ->
                addView(ui.rxCard {
                    addView(ui.rxRow(a.itemIcon(FfiItemType.IDENTITY, 40), a.t("Profil", "Profile"), p.title, chevron = true) { a.items.detail(p.vaultId, p.id) })
                })
            }
        }
    }

    /** Récents: the last items opened (until OnePass locks), how long ago, "Tout voir". */
    private fun recentCard(active: List<FfiItemSummary>): View = ui.rxCard {
        val byId = active.associateBy { it.id }
        val recents = a.recents.mapNotNull { byId[it] }
        addView(ui.rxCardHeader(a.t("Récents", "Recents"), if (recents.isEmpty()) null else ui.rxLink(a.t("Tout voir", "See All")) {
            a.push { list(a.t("Tous les éléments", "All Items"), active) }
        }))
        if (recents.isEmpty()) addView(ui.rxMessage(a.t("Les éléments que tu ouvres apparaissent ici jusqu'au verrouillage.", "Items you open appear here until OnePass locks.")))
        recents.take(3).forEach { s ->
            val ago = a.openedAt[s.id]?.let { at ->
                if (System.currentTimeMillis() - at < 60_000) a.t("maintenant", "now")
                else android.text.format.DateUtils.getRelativeTimeSpanString(at, System.currentTimeMillis(), android.text.format.DateUtils.MINUTE_IN_MILLIS, android.text.format.DateUtils.FORMAT_ABBREV_RELATIVE).toString()
            }
            addView(ui.rxRow(a.itemIcon(s.itemType, 40, s.favorite, s.primaryUrl, s.title), s.title.ifBlank { a.t("Sans titre", "Untitled") }, a.secondLine(s), ago) { a.items.detail(s.vaultId, s.id) })
        }
    }

    /** Favoris as a carousel: tiles one after the other, the next one peeking. */
    private fun favoritesCard(active: List<FfiItemSummary>): View = ui.rxCard {
        addView(ui.rxCardHeader(a.t("Favoris", "Favorites")))
        val favorites = active.filter { it.favorite }.sortedBy { it.title.lowercase() }
        if (favorites.isEmpty()) {
            addView(ui.rxMessage(a.t("Touche l'étoile d'un élément pour le retrouver ici.", "Tap an item's star to find it here.")))
        } else {
            addView(ui.carousel(favorites.map { s ->
                ui.favoriteTile(a.itemIcon(s.itemType, 64, url = s.primaryUrl, title = s.title), s.title.ifBlank { a.t("Sans titre", "Untitled") }) { a.items.detail(s.vaultId, s.id) }
            }))
        }
    }

    private fun vaultsCard(active: List<FfiItemSummary>): View = ui.rxCard {
        addView(ui.rxCardHeader(a.t("Coffres", "Vaults")))
        a.vaults.sortedBy { it.meta.name.lowercase() }.forEach { v ->
            val inVault = active.filter { it.vaultId == v.id }
            addView(ui.rxRow(ui.monogram(v.meta.name.take(1).uppercase(), Ios.vaultColor(v.meta.color), 40), v.meta.name, a.countLabel(inVault.size), chevron = true) {
                a.push { list(v.meta.name, inVault) }
            })
        }
    }

    private fun firstItemState(): View = LinearLayout(a).apply {
        orientation = LinearLayout.VERTICAL
        gravity = Gravity.CENTER
        setPadding(ui.dp(32), ui.dp(80), ui.dp(32), ui.dp(40))
        val fan = LinearLayout(a).apply { gravity = Gravity.CENTER }
        listOf(FfiItemType.LOGIN, FfiItemType.CREDIT_CARD, FfiItemType.IDENTITY, FfiItemType.SECURE_NOTE).forEachIndexed { i, type ->
            fan.addView(a.itemIcon(type, 64).apply {
                rotation = i * 8f - 12f
                elevation = ui.dp(4).toFloat()
                (layoutParams as LinearLayout.LayoutParams).marginStart = if (i == 0) 0 else -ui.dp(10)
            })
        }
        addView(fan)
        addView(ui.text(a.t("Ton coffre est vide", "Your Vault Is Empty"), 22f, ui.label, 700).apply { setPadding(0, ui.dp(24), 0, ui.dp(8)); gravity = Gravity.CENTER })
        addView(ui.text(a.t("Mots de passe, cartes, identités, notes : tout ce que tu ranges ici est chiffré sur tes appareils.",
            "Passwords, cards, identities, notes: everything you keep here is encrypted on your devices."), 16f, ui.secondary).apply { gravity = Gravity.CENTER })
        addView(ui.capsule(a.t("Créer ton premier élément", "Create Your First Item")) { a.items.newItem(null) },
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = ui.dp(20) })
    }

    // ---- Éléments ---------------------------------------------------------------------------------

    fun itemsTab(): View = a.rootPage(a.t("Éléments", "Items"), large = true, options = null) {
        val all = a.summaries
        val active = a.active
        addView(ui.inset(ui.card(
            ui.row(icon = ui.symbolTile(R.drawable.ic_grid, ui.accent), title = a.t("Tous les éléments", "All Items"), value = active.size.toString()) {
                a.push { list(a.t("Tous les éléments", "All Items"), active) }
            },
            ui.row(icon = ui.symbolTile(R.drawable.ic_star_fill, ui.orange), title = a.t("Favoris", "Favorites"), value = active.count { it.favorite }.toString()) {
                a.push { list(a.t("Favoris", "Favorites"), active.filter { it.favorite }) }
            },
        ), top = Ios.Space.S))

        addView(ui.sectionHeader(a.t("Coffres", "Vaults")))
        val vaultRows = a.vaults.sortedBy { it.meta.name.lowercase() }.map { v ->
            ui.row(icon = ui.monogram(v.meta.name.take(1).uppercase(), Ios.vaultColor(v.meta.color), 30, square = true), title = v.meta.name,
                value = active.count { it.vaultId == v.id }.toString()) { a.push { list(v.meta.name, active.filter { it.vaultId == v.id }) } }
        } + ui.row(icon = ui.glyph(R.drawable.ic_add, ui.accent, 24).apply { layoutParams = LinearLayout.LayoutParams(ui.dp(30), ui.dp(24)) },
            title = a.t("Nouveau coffre", "New Vault"), titleColor = ui.readableAccent, chevron = false) { a.settings.vaultEditor(null) }
        addView(ui.inset(ui.card(*vaultRows.toTypedArray())))

        val present = me.somalabs.onepass.ui.Category.ALL.filter { c -> active.any { it.itemType == c.type } }
        if (present.isNotEmpty()) {
            addView(ui.sectionHeader(a.t("Catégories", "Categories")))
            addView(ui.inset(ui.card(*present.map { c ->
                ui.row(icon = a.itemIcon(c.type, 30), title = c.plural(a), value = active.count { it.itemType == c.type }.toString()) {
                    a.push { list(c.plural(a), active.filter { it.itemType == c.type }) }
                }
            }.toTypedArray())))
        }

        val tags = active.flatMap { it.tags }.distinct().sortedBy { it.lowercase() }
        if (tags.isNotEmpty()) {
            addView(ui.sectionHeader("Tags"))
            addView(ui.inset(ui.card(*tags.map { tag ->
                ui.row(icon = ui.glyph(R.drawable.ic_tag, ui.secondary, 24), title = tag, value = active.count { tag in it.tags }.toString()) {
                    a.push { list(tag, active.filter { tag in it.tags }) }
                }
            }.toTypedArray())))
        }

        val archived = all.filter { it.archived && it.trashedAt == null }
        val trashed = all.filter { it.trashedAt != null }
        addView(ui.inset(ui.card(
            ui.row(icon = ui.glyph(R.drawable.ic_archive, ui.secondary, 24), title = a.t("Archive", "Archive"), value = archived.size.toString()) {
                a.push { list(a.t("Archive", "Archive"), archived) }
            },
            ui.row(icon = ui.glyph(R.drawable.ic_trash, ui.secondary, 24), title = a.t("Supprimés récemment", "Recently Deleted"), value = trashed.size.toString()) {
                a.push { trash() }
            },
        ), top = Ios.Space.XL))
    }

    /** An item list pushed from a tile or a row (CategoryListView). */
    fun list(title: String, items: List<FfiItemSummary>): View = a.pushedPage(title, largeTitle = true) {
        addView(ui.footnote(a.countLabel(items.size), ui.tertiary))
        addView(a.itemsCard(items.sortedBy { it.title.lowercase() }, a.t("Aucun élément.", "No items.")))
    }

    private fun trash(): View {
        val trashed = a.summaries.filter { it.trashedAt != null }
        val empty = a.barText(a.t("Vider", "Empty"), color = ui.red) {
            a.confirm(a.t("Supprimer définitivement ${a.countLabel(trashed.size)} ? Cette action est irréversible.",
                "Permanently delete ${a.countLabel(trashed.size)}? This cannot be undone."), a.t("Supprimer", "Delete")) {
                val s = a.session() ?: return@confirm
                a.background({ trashed.forEach { s.deleteItem(it.vaultId, it.id) } }) { r ->
                    r.onFailure { a.toast(a.message(it)) }
                    a.changed()
                }
            }
        }
        return a.pushedPage(a.t("Supprimés récemment", "Recently Deleted"), trailing = if (trashed.isEmpty()) emptyList() else listOf(empty), largeTitle = true) {
            addView(ui.footnote(a.t("Les éléments restent ici 30 jours avant d'être supprimés.", "Items stay here for 30 days before they are deleted.")))
            addView(a.itemsCard(trashed.sortedByDescending { it.trashedAt }, a.t("La corbeille est vide.", "Trash is empty.")))
        }
    }

    // ---- Recherche -----------------------------------------------------------------------------------

    fun search(): View {
        val page = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL }
        val bar = ui.searchField(a.t("Titre, site, identifiant, tag", "Title, website, username, tag"))
        val input = bar.getChildAt(1) as EditText
        page.addView(bar, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { setMargins(ui.dp(16), ui.dp(12), ui.dp(16), ui.dp(4)) })
        val results = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL; setPadding(0, 0, 0, ui.dp(110)) }
        page.addView(android.widget.ScrollView(a).apply { isVerticalScrollBarEnabled = false; addView(results) },
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        fun fill(q: String) {
            results.removeAllViews()
            val active = a.active
            val query = q.trim().lowercase()
            if (query.isEmpty()) {
                if (a.recentSearches.isNotEmpty()) {
                    results.addView(ui.sectionHeader(a.t("Recherches récentes", "Recent Searches"), a.link(a.t("Effacer", "Clear")) { a.recentSearches.clear(); fill("") }))
                    results.addView(ui.inset(ui.card(*a.recentSearches.map { s ->
                        ui.row(icon = ui.glyph(R.drawable.ic_history, ui.secondary, 22), title = s, chevron = false) { input.setText(s); input.setSelection(s.length) }
                    }.toTypedArray())))
                }
                val byId = active.associateBy { it.id }
                val opened = a.recents.mapNotNull { byId[it] }
                if (opened.isNotEmpty()) {
                    results.addView(ui.sectionHeader(a.t("Ouverts récemment", "Recently Opened")))
                    results.addView(a.itemsCard(opened.take(6), ""))
                }
                val present = me.somalabs.onepass.ui.Category.ALL.filter { c -> active.any { it.itemType == c.type } }
                if (present.isNotEmpty()) {
                    results.addView(ui.sectionHeader(a.t("Parcourir", "Browse")))
                    results.addView(ui.inset(ui.card(*present.map { c ->
                        ui.row(icon = a.itemIcon(c.type, 30), title = c.plural(a)) { a.push { list(c.plural(a), active.filter { it.itemType == c.type }) } }
                    }.toTypedArray())))
                }
                return
            }
            val found = active.filter {
                it.title.lowercase().contains(query) || it.subtitle.lowercase().contains(query) ||
                    (it.primaryUrl ?: "").lowercase().contains(query) || it.tags.any { t -> t.lowercase().contains(query) }
            }.sortedBy { it.title.lowercase() }
            results.addView(ui.footnote(a.countLabel(found.size), ui.tertiary))
            results.addView(a.itemsCard(found, a.t("Aucun résultat pour « $q ».", "No results for “$q”.")))
        }
        input.addTextChangedListener(object : TextWatcher {
            override fun afterTextChanged(e: Editable?) = fill(e.toString())
            override fun beforeTextChanged(s: CharSequence?, st: Int, c: Int, af: Int) {}
            override fun onTextChanged(s: CharSequence?, st: Int, b: Int, c: Int) {}
        })
        input.imeOptions = android.view.inputmethod.EditorInfo.IME_ACTION_SEARCH or android.view.inputmethod.EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
        input.setOnEditorActionListener { _, _, _ ->
            val q = input.text.toString().trim()
            if (q.isNotEmpty()) { a.recentSearches.remove(q); a.recentSearches.add(0, q); while (a.recentSearches.size > 8) a.recentSearches.removeAt(a.recentSearches.lastIndex) }
            false
        }
        fill("")
        val col = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL }
        col.addView(ui.largeTitle(a.t("Rechercher", "Search")).apply { setPadding(ui.dp(16), ui.dp(16), ui.dp(16), 0) })
        col.addView(page, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        return col
    }

    companion object {
        /** Sidebar.watchtowerColor of the Apple app. */
        val WATCHTOWER_COLOR = Color.rgb(0xE1, 0x4D, 0x3C)
    }
}
