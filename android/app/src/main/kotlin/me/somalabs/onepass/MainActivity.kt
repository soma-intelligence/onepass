package me.somalabs.onepass

import android.app.Activity
import android.app.AlertDialog
import android.app.Dialog
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.pm.ApplicationInfo
import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.Window
import android.view.WindowManager
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.PopupWindow
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import java.util.concurrent.Executors
import me.somalabs.onepass.core.FfiItemSummary
import me.somalabs.onepass.core.OnePassException
import me.somalabs.onepass.core.Session
import me.somalabs.onepass.screens.AccessScreens
import me.somalabs.onepass.screens.BrowseScreens
import me.somalabs.onepass.screens.ItemScreens
import me.somalabs.onepass.screens.SettingsScreens
import me.somalabs.onepass.screens.WatchtowerScreen
import me.somalabs.onepass.ui.Ios
import me.somalabs.onepass.vault.DeviceVault
import me.somalabs.onepass.vaultkit.core.CoreLoader
import me.somalabs.onepass.wifi.VaultWifi
import me.somalabs.onepass.wifi.WifiAutomation

/**
 * The app shell, laid out like the iPhone app (`PhoneTabsView`): three tabs
 * (Accueil, Éléments, Watchtower, Rechercher) in an Android navigation bar
 * (`showTabBar`), one navigation stack per tab, the root toolbar (account
 * avatar and its menu on the left, options and "+" on the right), sheets.
 * Screens live in `screens/`; the look in `ui/Ios`.
 *
 * Secrets: every window is FLAG_SECURE except in debuggable builds (emulator
 * tests take screenshots); a copied secret is marked sensitive (Android 13+)
 * and cleared after 90 s if the clipboard still holds it.
 */
/** The tag of a page that draws under the status bar (an RX photo page). */
const val EDGE = "rx.edge"

/** The same, over a dark photo in both appearances: the status bar icons turn light. */
const val EDGE_ON_DARK = "rx.edge.dark"

class MainActivity : Activity() {
    lateinit var ui: Ios
    lateinit var vault: DeviceVault
    lateinit var wifi: WifiAutomation
    private lateinit var root: FrameLayout
    private lateinit var host: FrameLayout
    private var tabBar: View? = null
    private val worker = Executors.newSingleThreadExecutor()
    val main = Handler(Looper.getMainLooper())
    private val ticks = mutableListOf<Runnable>()

    val browse by lazy { BrowseScreens(this) }
    val items by lazy { ItemScreens(this) }
    val watchtower by lazy { WatchtowerScreen(this) }
    val access by lazy { AccessScreens(this) }
    val settings by lazy { SettingsScreens(this) }
    val watchFetcher by lazy { me.somalabs.onepass.vault.WatchtowerFetcher(applicationContext) }
    val duplicates by lazy { me.somalabs.onepass.screens.DuplicatesScreen(this) }
    val travel by lazy { me.somalabs.onepass.screens.TravelScreen(this) }
    val backups by lazy { me.somalabs.onepass.screens.BackupScreens(this) }
    /** The sync of this device's account (shared with the AutoFill service and the periodic job). */
    val sync by lazy { me.somalabs.onepass.vault.SyncManager.get(this) }
    val syncScreens by lazy { me.somalabs.onepass.screens.SyncScreens(this) }
    val pairing by lazy { me.somalabs.onepass.screens.PairingScreens(this) }
    /** Contacts, shared vaults, family (the state for the whole process, the screens). */
    val sharing by lazy { me.somalabs.onepass.vault.Sharing.get(this) }
    val sharingScreens by lazy { me.somalabs.onepass.screens.SharingScreens(this) }
    val familyScreens by lazy { me.somalabs.onepass.screens.FamilyScreens(this) }

    enum class Tab { HOME, ITEMS, WATCHTOWER, SEARCH }

    var tab = Tab.HOME
        private set
    private val stacks = mutableMapOf<Tab, MutableList<() -> View>>()

    /** Opened this session (Home "Récents", Search "Ouverts récemment"): cleared on lock. */
    val recents = mutableListOf<String>()
    /** Searches of this session (Search "Recherches récentes"): cleared on lock, never stored. */
    val recentSearches = mutableListOf<String>()

    val debuggable get() = applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0

    // What the pages draw from, loaded off the main thread by reload().
    var summaries: List<FfiItemSummary> = emptyList()
        private set
    var vaults: List<me.somalabs.onepass.core.FfiVault> = emptyList()
        private set
    var profileName: String = ""
        private set
    /** The last Watchtower report; null until computed after a change. */
    var report: me.somalabs.onepass.core.FfiWatchtowerReport? = null

    /** Active items (neither archived nor trashed). */
    val active get() = summaries.filter { !it.archived && it.trashedAt == null }

    /** Reloads items and vaults, then [done] (by default, redraws). */
    fun reload(done: () -> Unit = { render() }) {
        val s = vault.session ?: return route()
        background({
            sharing.readNow(s)
            Triple(s.itemSummaries(), s.vaults(), runCatching { s.profile()?.name }.getOrNull().orEmpty())
        }) { r ->
            r.onSuccess {
                summaries = it.first
                vaults = it.second
                profileName = it.third
                report = null
                done()
                watchtower.ensureReport()
            }.onFailure {
                if (it is OnePassException.Locked) lockNow() else toast(message(it))
            }
        }
    }

    /** After a change to the vault: Wi-Fi networks follow, the sync sends it (debounced), the lists reload. */
    fun changed(done: () -> Unit = { render() }) {
        VaultWifi.changed(wifi)
        sync.localChange()
        reload(done)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!debuggable) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        actionBar?.hide()
        CoreLoader.ensureLoaded()
        ui = Ios(this)
        vault = DeviceVault.get(this)
        wifi = WifiAutomation.get(this)
        // Dark status and navigation bar icons on the light grouped page, as on iPhone.
        if (!ui.dark && Build.VERSION.SDK_INT >= 30) {
            val light = android.view.WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS or android.view.WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS
            window.insetsController?.setSystemBarsAppearance(light, light)
        }
        root = FrameLayout(this).apply { setBackgroundColor(ui.page) }
        host = FrameLayout(this)
        root.addView(host, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        // Edge to edge: the RX pages draw their photo under the status bar (`statusTop`), the
        // others get it as padding of the host.
        root.setOnApplyWindowInsetsListener { v, insets ->
            if (Build.VERSION.SDK_INT >= 30) {
                val bars = insets.getInsets(android.view.WindowInsets.Type.systemBars() or android.view.WindowInsets.Type.ime())
                v.setPadding(bars.left, 0, bars.right, bars.bottom)
                statusTop = bars.top
            } else {
                @Suppress("DEPRECATION")
                v.setPadding(insets.systemWindowInsetLeft, 0, insets.systemWindowInsetRight, insets.systemWindowInsetBottom)
                @Suppress("DEPRECATION")
                statusTop = insets.systemWindowInsetTop
            }
            fitPage()
            // The navigation bar reaches under the gesture bar: redraw it for the new inset.
            if (tabBar != null) v.post { if (tabBar != null) showTabBar() }
            insets
        }
        setContentView(root)
        me.somalabs.onepass.screens.Attachments.clearCache(this)
        // Sync: the coordinator of a mailbox account, the lists reload when changes arrive, the
        // periodic background round.
        sync.start()
        sync.onRemoteChange { afterSyncRound() }
        // A zone round brought changes (invitations, shared vaults, family): key requests answered, lists read again.
        sync.onZoneChange { afterSyncRound() }
        takeLink(intent)
        me.somalabs.onepass.vault.SyncJob.schedule(this)
        // The brand icons, mapped once off the main thread; the lists redraw with them.
        Thread { me.somalabs.onepass.ui.IconPack.load(applicationContext); main.post { if (!isDestroyed) renderIfRoot() } }.start()
        route()
    }

    /** After a sync round brought changes: the members' key requests answered, then everything read again. */
    private fun afterSyncRound() {
        val s = vault.session ?: return
        if (isDestroyed) return
        background({ sharing.afterRound(s) }) { reload { renderIfRoot() } }
    }

    override fun onNewIntent(intent: android.content.Intent) {
        super.onNewIntent(intent)
        takeLink(intent)
        if (vault.session != null) openPendingLink()
    }

    /** A contact invitation opened from another app (`onepass://contact/...`): answered once unlocked. */
    private fun takeLink(intent: android.content.Intent?) {
        val uri = intent?.data ?: return
        if (intent.action == android.content.Intent.ACTION_VIEW && uri.scheme == "onepass" && uri.host == "contact") {
            sharing.pendingLink = uri.toString()
            intent.data = null
        }
    }

    private fun openPendingLink() {
        val link = sharing.pendingLink ?: return
        sharing.pendingLink = null
        sharingScreens.openLink(link)
    }

    override fun onStart() {
        super.onStart()
        if (vault.lockIfIdle()) lockNow()
        sync.enterForeground()
    }

    override fun onStop() {
        sync.enterBackground()
        super.onStop()
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        vault.touch()
    }

    override fun onDestroy() {
        stopTicks()
        worker.shutdown()
        super.onDestroy()
    }

    // ---- helpers -----------------------------------------------------------------------

    fun t(fr: String, en: String) = if (resources.configuration.locales[0].language == "fr") fr else en

    fun <T> background(work: () -> T, done: (Result<T>) -> Unit) {
        worker.execute {
            val r = runCatching(work)
            main.post { if (!isDestroyed) done(r) }
        }
    }

    fun toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()

    fun message(e: Throwable): String = when (e) {
        is OnePassException.WrongPassword -> t("Mot de passe incorrect.", "Wrong password.")
        is OnePassException.Validation -> t("Champ « ${e.field} » : ${e.reason}", "Field “${e.field}”: ${e.reason}")
        is OnePassException.Locked -> t("OnePass est verrouillé.", "OnePass is locked.")
        is OnePassException.ReadOnlyRole -> t("Tu peux seulement consulter ce coffre.", "You can only view this vault.")
        is OnePassException.IdentityPending -> t("Un gestionnaire du coffre doit confirmer tes nouvelles clés avant que tu puisses modifier.", "A vault manager must confirm your new keys before you can make changes.")
        is OnePassException.ContactNotVerified -> t("Vérifie d'abord ce contact en personne ou avec son numéro de sécurité.", "Verify this contact in person or with their safety number first.")
        is OnePassException -> t("Erreur : ", "Error: ") + e.javaClass.simpleName
        else -> t("Erreur : ", "Error: ") + (e.message ?: e.javaClass.simpleName)
    }

    fun session(): Session? = vault.session ?: run { route(); null }

    /** Runs every second while the current page is shown (TOTP codes). */
    fun tick(r: Runnable) {
        ticks.add(r)
        main.post(r)
    }

    private fun stopTicks() {
        ticks.forEach(main::removeCallbacks)
        ticks.clear()
    }

    fun copy(value: String, secret: Boolean) {
        val cm = getSystemService(ClipboardManager::class.java)
        val clip = ClipData.newPlainText("OnePass", value)
        if (secret && Build.VERSION.SDK_INT >= 33) {
            clip.description.extras = PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) }
        }
        cm.setPrimaryClip(clip)
        toast(if (secret) t("Copié · effacé dans 90 s", "Copied · cleared in 90 s") else t("Copié", "Copied"))
        if (secret) {
            main.postDelayed({
                val now = runCatching { cm.primaryClip?.getItemAt(0)?.text?.toString() }.getOrNull()
                if (now == value) cm.clearPrimaryClip()
            }, 90_000)
        }
    }

    // ---- routing ---------------------------------------------------------------------------

    fun route() {
        background({ vault.state() }) { r ->
            when (r.getOrNull()) {
                DeviceVault.State.EMPTY -> showFull { access.intro() }
                DeviceVault.State.LOCKED -> showFull { access.lock() }
                DeviceVault.State.UNLOCKED -> openTabs()
                DeviceVault.State.NO_DEVICE_FILE -> showFull { access.restore(missingKey = true) }
                DeviceVault.State.MISSING -> showFull { access.problem(t("Le compte de cet appareil a disparu du coffre. C'est une anomalie d'intégrité : OnePass ne crée pas de compte par-dessus.", "This device's account is gone from the vault. That is an integrity fault: OnePass does not create an account over it.")) }
                null -> showFull { access.problem(message(r.exceptionOrNull()!!)) }
            }
        }
    }

    fun lockNow() {
        vault.lock()
        VaultWifi.locked(wifi)
        recents.clear()
        openedAt.clear()
        recentSearches.clear()
        stacks.clear()
        noTabs.clear()
        guards.clear()
        watchFetcher.clear()
        sharing.clear()
        me.somalabs.onepass.screens.Attachments.clearCache(this)
        route()
    }

    /** A screen without tabs (lock, onboarding). */
    fun showFull(build: () -> View) {
        stopTicks()
        setBack(null)
        tabBar?.let { root.removeView(it) }
        tabBar = null
        host.removeAllViews()
        host.addView(build(), FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        fitPage()
    }

    /** The status bar's height: an RX page (`EDGE` tag) draws under it, others start below it. */
    var statusTop = 0
        private set

    /** Pads the host for the page shown, and picks light or dark status bar icons for it. */
    private fun fitPage() {
        if (!::host.isInitialized) return
        val page = host.getChildAt(0)
        val edge = page?.tag == EDGE || page?.tag == EDGE_ON_DARK
        host.setPadding(0, if (edge) 0 else statusTop, 0, 0)
        if (Build.VERSION.SDK_INT >= 30) {
            val darkIcons = !ui.dark && page?.tag != EDGE_ON_DARK
            val mask = android.view.WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS
            window.insetsController?.setSystemBarsAppearance(if (darkIcons) mask else 0, mask)
        }
    }

    fun openTabs(start: Tab = Tab.HOME) {
        session()?.let { VaultWifi.opened(wifi, it) }
        // Contact invitations: the replies awaited before a restart, a link opened while locked.
        sharing.resumePending(profileName.ifBlank { Build.MODEL ?: "Android" })
        main.post { openPendingLink() }
        stacks.clear()
        noTabs.clear()
        tab = start
        reload()
    }

    private fun rootPage(t: Tab): () -> View = when (t) {
        Tab.HOME -> { { browse.home() } }
        Tab.ITEMS -> { { browse.itemsTab() } }
        Tab.WATCHTOWER -> { { watchtower.screen() } }
        Tab.SEARCH -> { { browse.search() } }
    }

    private fun stack(t: Tab) = stacks.getOrPut(t) { mutableListOf(rootPage(t)) }

    fun selectTab(t: Tab) {
        if (t == tab) {
            // Tapping the current tab pops to its root, as on iPhone.
            stacks[t] = mutableListOf(rootPage(t))
        }
        tab = t
        render()
    }

    /** Pushes a page on the current tab's stack. */
    /** Pages shown without the tab bar (the editor, as the iPhone's full-screen sheet). */
    private val noTabs = mutableSetOf<() -> View>()

    /** Pages that ask before they are left (the editor with unsaved changes). */
    private val guards = mutableMapOf<() -> View, (leave: () -> Unit) -> Unit>()

    fun push(tabs: Boolean = true, guard: ((leave: () -> Unit) -> Unit)? = null, build: () -> View) {
        if (!tabs) noTabs.add(build)
        guard?.let { guards[build] = it }
        stack(tab).add(build)
        render()
    }

    /** Back: the top page's guard decides first. */
    fun pop() {
        val top = stack(tab).last()
        val g = guards[top]
        if (g != null) g { if (stack(tab).lastOrNull() === top) popNow() } else popNow()
    }

    /** Leaves the top page without asking. */
    fun popNow() {
        val s = stack(tab)
        if (s.size > 1) s.removeAt(s.lastIndex).let { noTabs.remove(it); guards.remove(it) }
        render()
    }

    // ---- activity results (file pickers) -----------------------------------------------------

    private val results = mutableMapOf<Int, (Int, android.content.Intent?) -> Unit>()
    private var nextRequest = 1000

    /** Starts an activity for its result (SAF pickers, system settings). */
    fun launch(intent: android.content.Intent, done: (resultCode: Int, data: android.content.Intent?) -> Unit) {
        val code = nextRequest++
        results[code] = done
        try {
            startActivityForResult(intent, code)
        } catch (e: android.content.ActivityNotFoundException) {
            results.remove(code)
            toast(message(e))
        }
    }

    @Deprecated("Framework Activity results")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: android.content.Intent?) {
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
        results.remove(requestCode)?.invoke(resultCode, data)
    }

    /** Redraws only when a tab root is shown (a pushed page keeps what is typed). */
    fun renderIfRoot() {
        if (vault.session != null && stack(tab).size == 1) render()
    }

    /** Redraws the top page of the current tab (after a change). */
    fun render() {
        if (vault.session == null) return route()
        stopTicks()
        val s = stack(tab)
        host.removeAllViews()
        host.addView(s.last()(), FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        fitPage()
        setBack(if (s.size > 1) ({ pop() }) else if (tab != Tab.HOME) ({ selectTab(Tab.HOME) }) else null)
        if (s.last() in noTabs) {
            tabBar?.let { root.removeView(it) }
            tabBar = null
        } else showTabBar()
    }

    // ---- tab bar ------------------------------------------------------------------------------

    /**
     * An Android navigation bar (Material 3 layout, not the iPhone capsule): full width at the
     * bottom, opaque so nothing reads through it, rounded top corners, four destinations with
     * Search among them, and the active one marked by a pill behind its icon. It reaches under
     * the gesture bar (the root's bottom padding) so the system strip takes its colour.
     */
    private fun showTabBar() {
        tabBar?.let { root.removeView(it) }
        val inset = root.paddingBottom
        val bar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.TOP
            val top = ui.dp(24).toFloat()
            background = android.graphics.drawable.GradientDrawable().apply {
                setColor(ui.card)
                cornerRadii = floatArrayOf(top, top, top, top, 0f, 0f, 0f, 0f)
                setStroke(maxOf(1, ui.dp(0.5)), ui.hairline)
            }
            elevation = ui.dp(8).toFloat()
            setPadding(ui.dp(8), ui.dp(12), ui.dp(8), ui.dp(6) + inset)
        }
        fun item(t: Tab, icon: Int, iconOn: Int, label: String) {
            val on = tab == t
            val tint = if (on) ui.readableAccent else ui.secondary
            val cell = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                gravity = Gravity.CENTER_HORIZONTAL
                contentDescription = label
                isClickable = true
                isSelected = on
                setOnClickListener { selectTab(t) }
            }
            val pill = FrameLayout(this).apply {
                background = ui.pressable(if (on) ui.rounded(ui.accentSoft, 16) else null, 16)
                isDuplicateParentStateEnabled = true
                addView(ui.glyph(if (on) iconOn else icon, tint, 24), FrameLayout.LayoutParams(ui.dp(24), ui.dp(24), Gravity.CENTER))
            }
            cell.addView(pill, LinearLayout.LayoutParams(ui.dp(64), ui.dp(32)))
            cell.addView(ui.text(label, 12f, if (on) ui.label else ui.secondary, if (on) 700 else 500).apply {
                gravity = Gravity.CENTER; maxLines = 1; setPadding(0, ui.dp(4), 0, 0)
            })
            bar.addView(cell, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        }
        item(Tab.HOME, R.drawable.ic_home, R.drawable.ic_home_fill, t("Accueil", "Home"))
        item(Tab.ITEMS, R.drawable.ic_items, R.drawable.ic_items_fill, t("Éléments", "Items"))
        item(Tab.WATCHTOWER, R.drawable.ic_watchtower, R.drawable.ic_watchtower, "Watchtower")
        item(Tab.SEARCH, R.drawable.ic_search, R.drawable.ic_search, t("Rechercher", "Search"))
        root.clipToPadding = false
        val lp = FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.BOTTOM)
        lp.bottomMargin = -inset
        root.addView(bar, lp)
        tabBar = bar
    }

    // ---- page scaffolding ------------------------------------------------------------------------

    /**
     * A root page of a tab: toolbar (account avatar and menu, options, "+"),
     * an optional inline title, then the content, scrolling under the tab bar.
     */
    fun rootPage(title: String?, large: Boolean, options: (() -> Unit)?, content: LinearLayout.() -> Unit): View {
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, 0, 0, ui.dp(110))
        }
        val bar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(ui.dp(16), ui.dp(8), ui.dp(16), ui.dp(4))
        }
        bar.addView(accountButton())
        bar.addView(ui.text(if (!large && title != null) title else "", 17f, ui.label, 600).apply { gravity = Gravity.CENTER },
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        options?.let { bar.addView(ui.roundButton(R.drawable.ic_options, t("Afficher", "Show")) { it() }.apply { (layoutParams as LinearLayout.LayoutParams).marginEnd = ui.dp(10) }) }
        bar.addView(ui.roundButton(R.drawable.ic_add, t("Nouvel élément", "New item")) { items.newItem(null) })
        col.addView(bar)
        if (large && title != null) col.addView(ui.largeTitle(title))
        col.content()
        return ScrollView(this).apply {
            isFillViewport = true
            isVerticalScrollBarEnabled = false
            addView(col)
        }
    }

    /** A pushed page: round back button, optional trailing actions, then content. */
    fun pushedPage(title: String?, trailing: List<View> = emptyList(), largeTitle: Boolean = false, content: LinearLayout.() -> Unit): View {
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, 0, 0, ui.dp(110))
        }
        val bar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(ui.dp(16), ui.dp(8), ui.dp(16), ui.dp(4))
        }
        bar.addView(ui.roundButton(R.drawable.ic_chevron_left, t("Retour", "Back")) { pop() }.apply { (getChildAt(0) as android.widget.ImageView).imageTintList = android.content.res.ColorStateList.valueOf(ui.label) })
        bar.addView(ui.text(if (!largeTitle) title ?: "" else "", 17f, ui.label, 600).apply { gravity = Gravity.CENTER; maxLines = 1 },
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        if (trailing.isNotEmpty()) {
            val pill = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                background = ui.rounded(ui.glass, 22, ui.hairline)
                setPadding(ui.dp(6), 0, ui.dp(6), 0)
                minimumHeight = ui.dp(44)
            }
            trailing.forEach { pill.addView(it) }
            bar.addView(pill)
        } else {
            bar.addView(View(this), LinearLayout.LayoutParams(ui.dp(44), ui.dp(44)))
        }
        col.addView(bar)
        if (largeTitle && title != null) col.addView(ui.largeTitle(title))
        col.content()
        return ScrollView(this).apply {
            isFillViewport = true
            isVerticalScrollBarEnabled = false
            addView(col)
        }
    }

    /** A text action in a toolbar pill ("Modifier", "Enregistrer"). */
    fun barText(label: String, bold: Boolean = false, color: Int = ui.accent, onClick: () -> Unit) = ui.text(label, 17f, color, if (bold) 600 else 400).apply {
        setPadding(ui.dp(10), ui.dp(10), ui.dp(10), ui.dp(10))
        isClickable = true
        setOnClickListener { onClick() }
    }

    fun barIcon(res: Int, desc: String, color: Int = ui.readableAccent, onClick: (View) -> Unit) = FrameLayout(this).apply {
        contentDescription = desc
        isClickable = true
        setOnClickListener { onClick(this) }
        setPadding(ui.dp(10), ui.dp(10), ui.dp(10), ui.dp(10))
        addView(ui.glyph(res, color, 24))
    }

    // ---- account menu (PhoneRootToolbar) ------------------------------------------------------------

    fun accountButton(onPhoto: Boolean = false): View {
        val name = profileName
        val initials = name.split(" ").filter { it.isNotBlank() }.take(2).joinToString("") { it.first().uppercase() }.ifEmpty { "1" }
        val btn = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            isClickable = true
            contentDescription = t("Compte", "Account")
        }
        btn.addView(ui.monogram(initials, ui.accent, 36, square = true))
        btn.addView(ui.glyph(R.drawable.ic_chevron_down, if (onPhoto) Color.argb(0xCC, 255, 255, 255) else ui.secondary, 20).apply { (layoutParams as LinearLayout.LayoutParams).marginStart = ui.dp(2) })
        btn.setOnClickListener { accountMenu(btn, name) }
        return btn
    }

    private fun accountMenu(anchor: View, name: String) {
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = ui.rounded(ui.card, 20, ui.hairline)
            elevation = ui.dp(12).toFloat()
            setPadding(0, ui.dp(6), 0, ui.dp(6))
        }
        lateinit var pop: PopupWindow
        fun entry(icon: Int, label: String, color: Int = ui.label, action: () -> Unit) {
            col.addView(ui.row(icon = ui.glyph(icon, color, 22), title = label, titleColor = color, chevron = false, minHeightDp = 46) { pop.dismiss(); action() })
        }
        col.addView(ui.row(icon = ui.monogram(name.take(1).uppercase().ifEmpty { "1" }, ui.accent, 36, square = true),
            title = name.ifEmpty { t("Mon compte", "My account") }, subtitle = t("Appareil personnel", "Personal device"), chevron = false))
        col.addView(ui.separatorLine(16))
        entry(R.drawable.ic_settings, t("Réglages", "Settings")) { settings.open() }
        entry(R.drawable.ic_vault_new, t("Nouveau coffre", "New Vault")) { settings.vaultEditor(null) }
        col.addView(ui.separatorLine(16))
        entry(R.drawable.ic_lock, t("Verrouiller", "Lock"), ui.red) { lockNow() }
        pop = PopupWindow(col, ui.dp(280), ViewGroup.LayoutParams.WRAP_CONTENT, true).apply {
            setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
            elevation = ui.dp(12).toFloat()
        }
        pop.showAsDropDown(anchor, 0, ui.dp(6))
    }

    /** A popup menu of rows under `anchor` (field "⋯" menus, item "Actions"). */
    fun menu(anchor: View, entries: List<Triple<Int, String, () -> Unit>>, destructive: Set<String> = emptySet()) {
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = ui.rounded(ui.card, 16, ui.hairline)
            setPadding(0, ui.dp(4), 0, ui.dp(4))
        }
        lateinit var pop: PopupWindow
        entries.forEachIndexed { i, (icon, label, action) ->
            val color = if (label in destructive) ui.red else ui.label
            col.addView(ui.row(title = label, titleColor = color, chevron = false, minHeightDp = 44,
                trailing = ui.glyph(icon, color, 20)) { pop.dismiss(); action() })
            if (i < entries.lastIndex) col.addView(ui.separatorLine(16))
        }
        pop = PopupWindow(col, ui.dp(260), ViewGroup.LayoutParams.WRAP_CONTENT, true).apply {
            setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
            elevation = ui.dp(12).toFloat()
        }
        pop.showAsDropDown(anchor, -ui.dp(200), ui.dp(4))
    }

    // ---- sheets --------------------------------------------------------------------------------------

    /**
     * A sheet (iOS page sheet): rounded top, title, leading and trailing
     * actions. Returns the dialog so the content can close it.
     */
    fun sheet(title: String, leading: String?, trailing: Pair<String, (Dialog) -> Unit>?, content: (Dialog) -> View): Dialog {
        val d = Dialog(this, android.R.style.Theme_DeviceDefault_NoActionBar)
        d.requestWindowFeature(Window.FEATURE_NO_TITLE)
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = ui.rounded(ui.page, 26)
            // A dialog window wraps its content: fill the screen so the scroll area gets the rest.
            minimumHeight = resources.displayMetrics.heightPixels
        }
        val bar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(ui.dp(8), ui.dp(10), ui.dp(8), ui.dp(4))
        }
        // A bare View sized WRAP_CONTENT takes all the height it is offered: placeholders get 1 px.
        bar.addView(if (leading != null) barText(leading) { d.dismiss() } else View(this), LinearLayout.LayoutParams(ui.dp(110), if (leading != null) ViewGroup.LayoutParams.WRAP_CONTENT else 1))
        bar.addView(ui.text(title, 17f, ui.label, 600).apply { gravity = Gravity.CENTER }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        bar.addView(if (trailing != null) barText(trailing.first, bold = true) { trailing.second(d) }.apply { gravity = Gravity.END } else View(this),
            LinearLayout.LayoutParams(ui.dp(110), if (trailing != null) ViewGroup.LayoutParams.WRAP_CONTENT else 1))
        col.addView(bar)
        col.addView(ScrollView(this).apply { addView(content(d)) }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        col.setOnApplyWindowInsetsListener { v, insets ->
            val top = if (Build.VERSION.SDK_INT >= 30) insets.getInsets(android.view.WindowInsets.Type.systemBars()).top else @Suppress("DEPRECATION") insets.systemWindowInsetTop
            val bottom = if (Build.VERSION.SDK_INT >= 30) insets.getInsets(android.view.WindowInsets.Type.systemBars() or android.view.WindowInsets.Type.ime()).bottom else @Suppress("DEPRECATION") insets.systemWindowInsetBottom
            v.setPadding(0, top + ui.dp(12), 0, bottom)
            insets
        }
        d.setContentView(col, ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        d.window?.apply {
            setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
            setLayout(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
            if (!debuggable) addFlags(WindowManager.LayoutParams.FLAG_SECURE)
            attributes = attributes.apply { y = ui.dp(36) }
            setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
        }
        d.show()
        return d
    }

    fun confirm(message: String, action: String, destructive: Boolean = true, onYes: () -> Unit) {
        AlertDialog.Builder(this)
            .setMessage(message)
            .setPositiveButton(action) { _, _ -> onYes() }
            .setNegativeButton(t("Annuler", "Cancel"), null)
            .show()
            .getButton(AlertDialog.BUTTON_POSITIVE)
            .setTextColor(if (destructive) ui.red else ui.accent)
    }

    /** When each item of `recents` was opened (Home "Récents" shows how long ago). */
    val openedAt = mutableMapOf<String, Long>()

    /** Notes an item as opened (Home "Récents", Search "Ouverts récemment"). */
    fun opened(s: FfiItemSummary) {
        openedAt[s.id] = System.currentTimeMillis()
        recents.remove(s.id)
        recents.add(0, s.id)
        while (recents.size > 20) recents.removeAt(recents.lastIndex)
    }

    // ---- system back -------------------------------------------------------------------------------

    private var onBack: (() -> Unit)? = null
    private var backCallback: Any? = null

    private fun setBack(action: (() -> Unit)?) {
        onBack = action
        if (Build.VERSION.SDK_INT < 33) return
        val dispatcher = onBackInvokedDispatcher
        if (action != null && backCallback == null) {
            val cb = android.window.OnBackInvokedCallback { onBack?.invoke() }
            dispatcher.registerOnBackInvokedCallback(android.window.OnBackInvokedDispatcher.PRIORITY_DEFAULT, cb)
            backCallback = cb
        } else if (action == null && backCallback != null) {
            dispatcher.unregisterOnBackInvokedCallback(backCallback as android.window.OnBackInvokedCallback)
            backCallback = null
        }
    }

    /** Android 10 to 12 only: no back dispatcher there. Android 13+ never
     *  reaches this (setBack registers an OnBackInvokedCallback), so the
     *  gesture-back lint, which wants AndroidX, does not apply. */
    @Deprecated("Android 13+ uses OnBackInvokedDispatcher (setBack)")
    @android.annotation.SuppressLint("GestureBackNavigation")
    override fun onBackPressed() {
        val action = onBack
        if (action != null) action() else {
            @Suppress("DEPRECATION")
            super.onBackPressed()
        }
    }

    override fun onResume() {
        super.onResume()
        settings.onResume()
    }

    override fun onPause() {
        wifi.onReport = null
        super.onPause()
    }

    /** Shared: a TextView link-styled. */
    fun link(label: String, onClick: () -> Unit): TextView = ui.text(label, 15f, ui.readableAccent).apply {
        setPadding(ui.dp(16), ui.dp(10), ui.dp(16), ui.dp(10))
        isClickable = true
        setOnClickListener { onClick() }
    }
}
