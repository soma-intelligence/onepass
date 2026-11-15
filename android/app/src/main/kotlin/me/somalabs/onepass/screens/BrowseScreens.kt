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

/**
 * The item's icon, rounded, with the favorite star badge (ItemIcon + favoriteBadge): the site's
 * brand from the icon pack when its web address (or, without one, its title) has one, else the
 * category artwork.
 */
fun MainActivity.itemIcon(type: FfiItemType, sizeDp: Int, favorite: Boolean = false, url: String? = null, title: String? = null): View {
    val box = FrameLayout(this).apply { layoutParams = LinearLayout.LayoutParams(ui.dp(sizeDp), ui.dp(sizeDp)) }
    val pack = me.somalabs.onepass.ui.IconPack.shared
    val brand = if (pack == null || type !in brandTypes) null else me.somalabs.onepass.ui.IconPack.host(url)?.let { pack.forHost(it) }
        ?: title?.takeIf { url.isNullOrBlank() }?.let { pack?.forTitle(it) }
    val art: View = if (brand != null) FrameLayout(this).apply {
        background = ui.rounded(if (brand.monochrome) ui.card else android.graphics.Color.WHITE, sizeDp * 0.225f, ui.hairline)
        val pad = ui.dp(sizeDp * 0.16f)
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
        box.addView(badge, FrameLayout.LayoutParams(ui.dp(16), ui.dp(16), Gravity.END or Gravity.BOTTOM).apply { setMargins(0, 0, -ui.dp(3), -ui.dp(3)) })
        box.clipChildren = false
    }
    return box
}

/** The kinds that can carry a site's brand icon. */
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

    fun home(): View {
        val first = a.profileName.split(" ").firstOrNull { it.isNotBlank() }
        val greeting = if (first == null) a.t("Accueil", "Home") else a.t("Bonjour $first", "Hi $first")
        val active = a.active
        // The sharing notices on top (iPhone `SharingBanners`): a recovery request, invitations, changed keys, received items.
        val banners = a.sharingScreens.banners()
        if (active.isEmpty()) return a.rootPage(greeting, large = true, options = null) {
            banners?.let { addView(it) }
            addView(firstItemState(), LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        }
        return a.rootPage(greeting, large = true, options = { homeOptions() }) {
            banners?.let { addView(it) }
            addView(tiles(active))
            if (prefs.getBoolean("profile", true)) {
                active.filter { it.itemType == FfiItemType.IDENTITY }.minByOrNull { it.title.lowercase() }?.let { p ->
                    addView(ui.inset(ui.card(ui.row(icon = a.itemIcon(FfiItemType.IDENTITY, 40), title = a.t("Profil", "Profile"), subtitle = p.title, minHeightDp = 64) { a.items.detail(p.vaultId, p.id) }), top = Ios.Space.L))
                }
            }
            if (prefs.getBoolean("favorites", true)) {
                addView(foldCard("favoritesOpen", a.t("Favoris", "Favorites"), R.drawable.ic_star_fill, ui.orange,
                    active.filter { it.favorite }.sortedBy { it.title.lowercase() }, a.t("Touche l'étoile d'un élément pour le retrouver ici.", "Tap an item's star to find it here.")))
            }
            if (prefs.getBoolean("recents", true)) {
                val byId = active.associateBy { it.id }
                addView(foldCard("recentsOpen", a.t("Récents", "Recents"), R.drawable.ic_history, Color.rgb(0x8C, 0x8C, 0x8C),
                    a.recents.mapNotNull { byId[it] }, a.t("Les éléments ouverts apparaissent ici jusqu'au verrouillage.", "Items you open appear here until OnePass locks.")))
            }
        }
    }

    private fun homeOptions() {
        val keys = listOf("profile" to a.t("Profil", "Profile"), "favorites" to a.t("Favoris", "Favorites"), "recents" to a.t("Récents", "Recents"))
        val checked = keys.map { prefs.getBoolean(it.first, true) }.toBooleanArray()
        android.app.AlertDialog.Builder(a)
            .setTitle(a.t("Afficher sur l'accueil", "Show on Home"))
            .setMultiChoiceItems(keys.map { it.second }.toTypedArray(), checked) { _, i, on -> prefs.edit().putBoolean(keys[i].first, on).apply() }
            .setPositiveButton("OK") { _, _ -> a.render() }
            .show()
    }

    private fun tiles(active: List<FfiItemSummary>): View {
        val grid = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL; setPadding(ui.dp(16), ui.dp(4), ui.dp(16), 0) }
        fun tile(title: String, icon: Int, color: Int, value: View, onClick: () -> Unit) = LinearLayout(a).apply {
            orientation = LinearLayout.VERTICAL
            background = ui.pressable(ui.rounded(ui.card, Ios.Radius.CARD, ui.hairline), Ios.Radius.CARD)
            setPadding(ui.dp(16), ui.dp(16), ui.dp(16), ui.dp(16))
            isClickable = true
            contentDescription = title
            setOnClickListener { onClick() }
            val top = LinearLayout(a).apply { gravity = Gravity.CENTER_VERTICAL }
            top.addView(ui.symbolTile(icon, color, 34))
            top.addView(View(a), LinearLayout.LayoutParams(0, 1, 1f))
            top.addView(value)
            addView(top)
            addView(ui.text(title, 15f, ui.secondary, 600).apply { maxLines = 1; setPadding(0, ui.dp(12), 0, 0) })
        }
        fun figure(n: String, color: Int = ui.label) = ui.text(n, 22f, color, 700).apply { fontFeatureSettings = "tnum" }
        fun pair(l: View, r: View) = LinearLayout(a).apply {
            addView(l, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { marginEnd = ui.dp(6) })
            addView(r, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { marginStart = ui.dp(6) })
        }
        val score = a.report?.score?.toInt()
        grid.addView(pair(
            tile(a.t("Tous les éléments", "All Items"), R.drawable.ic_grid, ui.accent, figure(active.size.toString())) { a.push { list(a.t("Tous les éléments", "All Items"), active) } },
            tile(a.t("Favoris", "Favorites"), R.drawable.ic_star_fill, ui.orange, figure(active.count { it.favorite }.toString())) {
                a.push { list(a.t("Favoris", "Favorites"), active.filter { it.favorite }) }
            },
        ))
        grid.addView(pair(
            tile("Watchtower", R.drawable.ic_watchtower, WATCHTOWER_COLOR,
                if (score != null) figure(score.toString(), WatchtowerScreen.scoreColor(ui, score)) else ui.glyph(R.drawable.ic_chevron_right, ui.tertiary, 20)) { a.selectTab(MainActivity.Tab.WATCHTOWER) },
            tile(a.t("À proximité", "Nearby"), R.drawable.ic_globe, ui.blue, ui.text("2 km", 15f, ui.secondary, 600)) { a.push { nearby() } },
        ), LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = ui.dp(12) })
        return grid
    }

    private fun nearby(): View = a.pushedPage(a.t("À proximité", "Nearby"), largeTitle = true) {
        addView(ui.footnote(a.t(
            "Les éléments qui ont un lieu (une adresse, un digicode) apparaîtront ici. La position n'est pas encore lue sur Android : rien n'est demandé à l'appareil.",
            "Items with a place (an address, a door code) will show here. Android does not read the location yet: nothing is asked of the device.")))
    }

    /** Favoris or Récents: the header (tile, count, fold chevron), then the rows. */
    private fun foldCard(key: String, title: String, icon: Int, color: Int, list: List<FfiItemSummary>, empty: String): View {
        val open = prefs.getBoolean(key, true)
        val col = LinearLayout(a).apply {
            orientation = LinearLayout.VERTICAL
            background = ui.rounded(ui.card, Ios.Radius.CARD, ui.hairline)
            clipToOutline = true
        }
        val header = LinearLayout(a).apply {
            gravity = Gravity.CENTER_VERTICAL
            setPadding(ui.dp(16), ui.dp(10), ui.dp(8), ui.dp(10))
            isClickable = true
            setOnClickListener { prefs.edit().putBoolean(key, !open).apply(); a.render() }
        }
        header.addView(ui.symbolTile(icon, color, 32))
        val names = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL; setPadding(ui.dp(12), 0, 0, 0) }
        names.addView(ui.text(title, 17f, ui.label, 600))
        if (list.isNotEmpty()) names.addView(ui.text(a.countLabel(list.size), 12f, ui.tertiary))
        header.addView(names, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        header.addView(ui.glyph(R.drawable.ic_chevron_down, ui.readableAccent, 18).apply { rotation = if (open) 0f else -90f; (layoutParams as LinearLayout.LayoutParams).marginEnd = ui.dp(8) })
        col.addView(header)
        if (open) {
            if (list.isEmpty()) {
                col.addView(ui.text(empty, 15f, ui.secondary).apply { setPadding(ui.dp(16), 0, ui.dp(16), ui.dp(16)) })
            } else {
                list.take(8).forEach { s ->
                    col.addView(ui.separatorLine(64))
                    col.addView(a.itemRow(s))
                }
            }
        }
        return ui.inset(col, top = Ios.Space.L)
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
