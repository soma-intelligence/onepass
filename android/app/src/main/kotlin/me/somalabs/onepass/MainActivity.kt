package me.somalabs.onepass

import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.res.Configuration
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.provider.Settings
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.SeekBar
import android.widget.Spinner
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import java.text.DateFormat
import java.util.Date
import java.util.concurrent.Executors
import me.somalabs.onepass.core.FfiFieldType
import me.somalabs.onepass.core.FfiFieldValue
import me.somalabs.onepass.core.FfiItem
import me.somalabs.onepass.core.FfiItemSummary
import me.somalabs.onepass.core.FfiMatchRule
import me.somalabs.onepass.core.FfiPasswordRecipe
import me.somalabs.onepass.core.FfiUrl
import me.somalabs.onepass.core.FfiVault
import me.somalabs.onepass.core.OnePassException
import me.somalabs.onepass.core.generatePassword
import me.somalabs.onepass.core.itemTypes
import me.somalabs.onepass.core.passwordEntropyBits
import me.somalabs.onepass.core.totpNow
import me.somalabs.onepass.vault.DeviceVault
import me.somalabs.onepass.vaultkit.core.CoreLoader
import me.somalabs.onepass.wifi.SuggestionApproval
import me.somalabs.onepass.wifi.SyncReport
import me.somalabs.onepass.wifi.VaultWifi
import me.somalabs.onepass.wifi.WifiAutomation

/**
 * The whole app, one activity: create a vault, show the Secret Key once,
 * unlock, browse, read, add, edit, copy and trash items, generate passwords,
 * settings (automatic Wi-Fi, security). Plain Android views, no extra
 * dependency (every Gradle artifact is pinned and verified).
 *
 * Secrets: a secret field is drawn masked and its value is read from the core
 * only when the user asks to see or copy it; a copy is marked sensitive
 * (Android 13+) and cleared after 90 s if still ours. Every window is
 * FLAG_SECURE (no screenshot, no recent-apps preview) except in debuggable
 * builds, where screenshots serve the emulator tests.
 */
class MainActivity : Activity() {
    private lateinit var vault: DeviceVault
    private lateinit var wifi: WifiAutomation
    private lateinit var root: FrameLayout
    private val worker = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private val ticks = mutableListOf<Runnable>()

    // List state
    private var filter = Filter.ALL
    private var query = ""

    private enum class Filter { ALL, FAVORITES, TRASH }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val debuggable = applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        if (!debuggable) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        actionBar?.hide()
        CoreLoader.ensureLoaded()
        vault = DeviceVault.get(this)
        wifi = WifiAutomation.get(this)
        root = FrameLayout(this).apply { setBackgroundColor(c.bg) }
        root.setOnApplyWindowInsetsListener { v, insets ->
            val bars = insets.getInsets(android.view.WindowInsets.Type.systemBars() or android.view.WindowInsets.Type.ime())
            v.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }
        setContentView(root)
        route()
    }

    override fun onStart() {
        super.onStart()
        if (vault.lockIfIdle()) {
            VaultWifi.locked(wifi)
            route()
        }
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

    // ---- theme --------------------------------------------------------------------

    private class Palette(dark: Boolean) {
        val accent = if (dark) Color.rgb(0x7D, 0x7A, 0xFF) else Color.rgb(0x58, 0x56, 0xD6)
        val bg = if (dark) Color.rgb(0x1C, 0x1C, 0x1E) else Color.rgb(0xF5, 0xF5, 0xF7)
        val panel = if (dark) Color.rgb(0x2A, 0x2A, 0x2D) else Color.WHITE
        val ink = if (dark) Color.rgb(0xF5, 0xF5, 0xF7) else Color.rgb(0x1D, 0x1D, 0x1F)
        val ink2 = if (dark) Color.rgb(0xA1, 0xA1, 0xA6) else Color.rgb(0x6E, 0x6E, 0x73)
        val line = if (dark) Color.rgb(0x38, 0x38, 0x3C) else Color.rgb(0xE2, 0xE2, 0xE7)
        val danger = if (dark) Color.rgb(0xFF, 0x45, 0x3A) else Color.rgb(0xD7, 0x00, 0x15)
    }

    private val c: Palette by lazy {
        Palette(resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK == Configuration.UI_MODE_NIGHT_YES)
    }

    private fun dp(v: Int): Int = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v.toFloat(), resources.displayMetrics).toInt()

    private fun text(s: CharSequence, size: Float = 16f, color: Int = c.ink, bold: Boolean = false) =
        TextView(this).apply {
            text = s
            textSize = size
            setTextColor(color)
            if (bold) typeface = Typeface.DEFAULT_BOLD
        }

    private fun rounded(color: Int, radius: Int = 14, stroke: Int? = null) = GradientDrawable().apply {
        setColor(color)
        cornerRadius = dp(radius).toFloat()
        stroke?.let { setStroke(dp(1), it) }
    }

    private fun button(label: String, primary: Boolean = false, onClick: () -> Unit) =
        Button(this).apply {
            text = label
            isAllCaps = false
            textSize = 15f
            setTextColor(if (primary) Color.WHITE else c.accent)
            background = rounded(if (primary) c.accent else c.panel, 12, if (primary) null else c.line)
            setPadding(dp(16), dp(10), dp(16), dp(10))
            minHeight = dp(48)
            setOnClickListener { onClick() }
            filterTouchesWhenObscured = true
        }

    private fun field(hint: String, password: Boolean = false, value: String = "") =
        EditText(this).apply {
            this.hint = hint
            setText(value)
            textSize = 16f
            setTextColor(c.ink)
            setHintTextColor(c.ink2)
            background = rounded(c.panel, 10, c.line)
            setPadding(dp(14), dp(12), dp(14), dp(12))
            inputType = if (password) {
                InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            } else {
                InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            }
            // No learning from what is typed here (spec 7.1).
            imeOptions = EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
            // A password input type switches to monospace: keep the app's font.
            typeface = Typeface.DEFAULT
        }

    private fun column(padding: Int = 20) = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(padding), dp(padding), dp(padding), dp(padding))
    }

    private fun gap(h: Int) = View(this).apply { layoutParams = LinearLayout.LayoutParams(1, dp(h)) }

    private fun LinearLayout.add(v: View, top: Int = 0): View {
        // A view that set its own size (the logo) keeps it.
        val lp = (v.layoutParams as? LinearLayout.LayoutParams)
            ?: LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        lp.topMargin = dp(top)
        addView(v, lp)
        return v
    }

    // System back (predictive back, targetSdk 37: onBackPressed is not called):
    // a screen that sets [onBack] gets it, the others leave the app.
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

    /** Android 10 to 12: no back dispatcher. */
    @Deprecated("Android 13+ uses OnBackInvokedDispatcher (setBack)")
    override fun onBackPressed() {
        val action = onBack
        if (action != null) {
            action()
        } else {
            @Suppress("DEPRECATION")
            super.onBackPressed()
        }
    }

    private fun show(v: View, back: (() -> Unit)? = null) {
        setBack(back)
        settingsAttach = null
        wifi.onReport = null
        stopTicks()
        root.removeAllViews()
        root.addView(v, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
    }

    private fun scroll(content: View) = ScrollView(this).apply {
        isFillViewport = true
        addView(content)
    }

    private fun logo() = TextView(this).apply {
        text = "1"
        textSize = 22f
        typeface = Typeface.DEFAULT_BOLD
        setTextColor(Color.WHITE)
        gravity = Gravity.CENTER
        background = rounded(c.accent, 14)
        layoutParams = LinearLayout.LayoutParams(dp(52), dp(52))
    }

    private fun toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()

    private fun message(e: Throwable): String = when (e) {
        is OnePassException.WrongPassword -> getString(R.string.wrong_password)
        is OnePassException.Validation -> getString(R.string.invalid_field, e.field, e.reason)
        is OnePassException -> getString(R.string.error_prefix, e.javaClass.simpleName)
        else -> getString(R.string.error_prefix, e.message ?: e.javaClass.simpleName)
    }

    /** Runs [work] off the main thread, then [done] on it. */
    private fun <T> background(work: () -> T, done: (Result<T>) -> Unit) {
        worker.execute {
            val r = runCatching(work)
            main.post { if (!isDestroyed) done(r) }
        }
    }

    private fun stopTicks() {
        ticks.forEach(main::removeCallbacks)
        ticks.clear()
    }

    // ---- routing --------------------------------------------------------------------

    private fun route() {
        background({ vault.state() }) { r ->
            when (r.getOrNull()) {
                DeviceVault.State.EMPTY -> onboarding()
                DeviceVault.State.LOCKED -> unlockScreen()
                DeviceVault.State.UNLOCKED -> listScreen()
                DeviceVault.State.NO_DEVICE_FILE -> problem(getString(R.string.no_device_file))
                DeviceVault.State.MISSING -> problem(getString(R.string.account_missing))
                null -> problem(message(r.exceptionOrNull()!!))
            }
        }
    }

    private fun problem(detail: String) {
        val col = column(28)
        col.add(logo())
        col.add(text(getString(R.string.app_name), 24f, bold = true), 16)
        col.add(text(detail, 15f, c.ink2), 8)
        show(scroll(col))
    }

    // ---- onboarding --------------------------------------------------------------------

    private fun onboarding() {
        val col = column(28)
        col.add(logo())
        col.add(text(getString(R.string.welcome_title), 26f, bold = true), 20)
        col.add(text(getString(R.string.welcome_body), 15f, c.ink2), 8)
        val pw = field(getString(R.string.master_password), password = true)
        val pw2 = field(getString(R.string.master_password_again), password = true)
        val err = text("", 14f, c.danger)
        col.add(pw, 24)
        col.add(pw2, 12)
        col.add(err, 8)
        lateinit var go: Button
        go = button(getString(R.string.create_vault), primary = true) {
            val a = pw.text.toString()
            val b = pw2.text.toString()
            when {
                a != b -> err.text = getString(R.string.passwords_differ)
                a.length < 10 -> err.text = getString(R.string.password_too_short)
                else -> {
                    go.isEnabled = false
                    go.text = getString(R.string.creating)
                    err.text = ""
                    val chars = a.toCharArray()
                    pw.text.clear(); pw2.text.clear()
                    background({ vault.create(chars, Build.MODEL ?: "Android") }) { r ->
                        chars.fill(' ')
                        r.onSuccess { key ->
                            VaultWifi.opened(wifi, vault.session!!)
                            secretKeyScreen(key)
                        }.onFailure {
                            err.text = message(it)
                            go.isEnabled = true
                            go.text = getString(R.string.create_vault)
                        }
                    }
                }
            }
        }
        col.add(go, 12)
        show(scroll(col))
        pw.requestFocus()
    }

    private fun secretKeyScreen(secretKey: String) {
        val col = column(28)
        col.add(logo())
        col.add(text(getString(R.string.secret_key_title), 26f, bold = true), 20)
        col.add(text(getString(R.string.secret_key_body), 15f, c.ink2), 8)
        col.add(text(secretKey, 17f).apply {
            typeface = Typeface.MONOSPACE
            setTextIsSelectable(false)
            background = rounded(c.panel, 10, c.accent)
            setPadding(dp(14), dp(14), dp(14), dp(14))
        }, 16)
        val noted = CheckBox(this).apply {
            text = getString(R.string.secret_key_noted)
            setTextColor(c.ink)
        }
        col.add(noted, 16)
        val next = button(getString(R.string.continue_label), primary = true) { listScreen() }
        next.isEnabled = false
        next.alpha = 0.5f
        noted.setOnCheckedChangeListener { _, on ->
            next.isEnabled = on
            next.alpha = if (on) 1f else 0.5f
        }
        col.add(next, 12)
        show(scroll(col))
    }

    // ---- unlock ---------------------------------------------------------------------------

    private fun unlockScreen() {
        val col = column(28)
        col.add(logo())
        col.add(text(getString(R.string.locked_title), 26f, bold = true), 20)
        val body = text("", 15f, c.ink2)
        col.add(body, 8)
        background({ vault.protection }) { r -> body.text = getString(R.string.locked_body, r.getOrDefault("Android Keystore")) }
        val pw = field(getString(R.string.master_password), password = true)
        val err = text("", 14f, c.danger)
        col.add(pw, 24)
        col.add(err, 8)
        lateinit var go: Button
        val submit = {
            go.isEnabled = false
            go.text = getString(R.string.unlocking)
            err.text = ""
            val chars = pw.text.toString().toCharArray()
            background({ vault.unlock(chars) }) { r ->
                chars.fill(' ')
                r.onSuccess {
                    pw.text.clear()
                    VaultWifi.opened(wifi, vault.session!!)
                    listScreen()
                }.onFailure {
                    err.text = message(it)
                    pw.selectAll()
                    go.isEnabled = true
                    go.text = getString(R.string.unlock)
                }
            }
        }
        go = button(getString(R.string.unlock), primary = true) { submit() }
        pw.imeOptions = pw.imeOptions or EditorInfo.IME_ACTION_DONE
        pw.setOnEditorActionListener { _, action, _ -> if (action == EditorInfo.IME_ACTION_DONE) { submit(); true } else false }
        col.add(go, 12)
        show(scroll(col))
        pw.requestFocus()
    }

    private fun lockNow() {
        vault.lock()
        VaultWifi.locked(wifi)
        route()
    }

    // ---- list ---------------------------------------------------------------------------------

    private fun session() = vault.session ?: run { route(); null }

    private fun listScreen() {
        val s = session() ?: return
        val page = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }

        // Top bar
        val bar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(16), dp(8), dp(8), dp(8))
        }
        bar.addView(text(getString(R.string.app_name), 22f, bold = true), LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        fun icon(label: String, desc: String, onClick: () -> Unit) = TextView(this).apply {
            text = label
            textSize = 20f
            setTextColor(c.accent)
            gravity = Gravity.CENTER
            contentDescription = desc
            minWidth = dp(48); minHeight = dp(48)
            setOnClickListener { onClick() }
        }
        bar.addView(icon("⚙", getString(R.string.settings)) { settingsScreen() })
        bar.addView(icon("🎲", getString(R.string.generator)) { generatorDialog(null) })
        bar.addView(icon("🔒", getString(R.string.lock)) { lockNow() })
        page.addView(bar)

        val search = field(getString(R.string.search), value = query)
        val searchWrap = column(0).apply { setPadding(dp(16), 0, dp(16), dp(8)) }
        searchWrap.add(search)
        page.addView(searchWrap)

        // Filters
        val tabs = LinearLayout(this).apply { setPadding(dp(16), 0, dp(16), dp(8)) }
        page.addView(tabs)

        val list = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val listScroll = ScrollView(this).apply { addView(list) }
        val body = FrameLayout(this)
        body.addView(listScroll)
        val fab = TextView(this).apply {
            text = "+"
            textSize = 30f
            setTextColor(Color.WHITE)
            gravity = Gravity.CENTER
            background = rounded(c.accent, 30)
            elevation = dp(6).toFloat()
            contentDescription = getString(R.string.new_item)
            setOnClickListener { newItemDialog() }
        }
        body.addView(fab, FrameLayout.LayoutParams(dp(60), dp(60), Gravity.BOTTOM or Gravity.END).apply { setMargins(0, 0, dp(20), dp(20)) })
        page.addView(body, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))

        var items: List<FfiItemSummary> = emptyList()
        fun render() {
            tabs.removeAllViews()
            for ((f, label) in listOf(Filter.ALL to R.string.all_items, Filter.FAVORITES to R.string.favorites, Filter.TRASH to R.string.trash)) {
                val on = filter == f
                tabs.addView(TextView(this).apply {
                    text = getString(label)
                    textSize = 14f
                    setTextColor(if (on) Color.WHITE else c.ink)
                    background = rounded(if (on) c.accent else c.panel, 16, if (on) null else c.line)
                    setPadding(dp(14), dp(6), dp(14), dp(6))
                    setOnClickListener { filter = f; render() }
                }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { marginEnd = dp(8) })
            }
            list.removeAllViews()
            val q = query.trim().lowercase()
            val shown = items.filter {
                when (filter) {
                    Filter.TRASH -> it.trashedAt != null
                    Filter.FAVORITES -> it.trashedAt == null && !it.archived && it.favorite
                    Filter.ALL -> it.trashedAt == null && !it.archived
                }
            }.filter {
                q.isEmpty() || it.title.lowercase().contains(q) || it.subtitle.lowercase().contains(q) ||
                    (it.primaryUrl ?: "").lowercase().contains(q)
            }.sortedBy { it.title.lowercase() }
            if (shown.isEmpty()) {
                list.add(text(getString(if (q.isEmpty()) R.string.empty_list else R.string.no_result), 15f, c.ink2).apply {
                    gravity = Gravity.CENTER
                    setPadding(dp(24), dp(48), dp(24), dp(24))
                })
            }
            for (i in shown) {
                val row = LinearLayout(this).apply {
                    orientation = LinearLayout.HORIZONTAL
                    gravity = Gravity.CENTER_VERTICAL
                    setPadding(dp(16), dp(12), dp(16), dp(12))
                    setOnClickListener { detailScreen(i.vaultId, i.id) }
                }
                row.addView(TextView(this).apply {
                    text = (i.title.trim().firstOrNull() ?: '?').uppercase()
                    textSize = 18f
                    typeface = Typeface.DEFAULT_BOLD
                    setTextColor(c.accent)
                    gravity = Gravity.CENTER
                    background = rounded(Color.argb(40, Color.red(c.accent), Color.green(c.accent), Color.blue(c.accent)), 10)
                }, LinearLayout.LayoutParams(dp(42), dp(42)).apply { marginEnd = dp(14) })
                val texts = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
                texts.addView(text((if (i.favorite) "★ " else "") + i.title.ifBlank { getString(R.string.untitled) }, 16f).apply { maxLines = 1 })
                texts.addView(text(i.subtitle.ifBlank { typeLabel(i.itemType) }, 13f, c.ink2).apply { maxLines = 1 })
                row.addView(texts, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
                list.addView(row)
                list.addView(View(this).apply { setBackgroundColor(c.line) }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 1))
            }
        }
        search.addTextChangedListener(object : TextWatcher {
            override fun afterTextChanged(e: Editable?) { query = e.toString(); render() }
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, d: Int) {}
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, d: Int) {}
        })
        show(page)
        render()
        background({ s.itemSummaries() }) { r ->
            r.onSuccess { items = it; render() }.onFailure { toast(message(it)); if (it is OnePassException.Locked) route() }
        }
    }

    private val types by lazy { itemTypes() }

    private fun typeLabel(t: me.somalabs.onepass.core.FfiItemType): String =
        types.firstOrNull { it.itemType == t }?.label ?: t.name

    // ---- detail ------------------------------------------------------------------------------------

    private fun isSecret(k: FfiFieldType) = k == FfiFieldType.PASSWORD || k == FfiFieldType.CONCEALED ||
        k == FfiFieldType.OTP || k == FfiFieldType.MNEMONIC || k == FfiFieldType.SSH_KEY

    private fun display(v: FfiFieldValue): String? = when (v) {
        is FfiFieldValue.Text -> v.value
        is FfiFieldValue.Concealed -> v.value
        is FfiFieldValue.Password -> v.value
        is FfiFieldValue.Url -> v.value
        is FfiFieldValue.Email -> v.value
        is FfiFieldValue.Phone -> v.value
        is FfiFieldValue.Menu -> v.value
        is FfiFieldValue.Otp -> v.value
        is FfiFieldValue.Mnemonic -> v.value
        is FfiFieldValue.Number -> v.value.toString()
        is FfiFieldValue.Date -> "%04d-%02d-%02d".format(v.value.year, v.value.month.toInt(), v.value.day.toInt())
        is FfiFieldValue.MonthYear -> "%02d/%04d".format(v.month.toInt(), v.year.toInt())
        is FfiFieldValue.Money -> "%d.%02d %s".format(v.minorUnits / 100, kotlin.math.abs(v.minorUnits % 100), v.currency)
        is FfiFieldValue.Address -> listOf(v.value.line1, v.value.line2, v.value.postalCode, v.value.city, v.value.region, v.value.country).filter { it.isNotBlank() }.joinToString(", ")
        is FfiFieldValue.SshKey -> v.value.privatePem
        is FfiFieldValue.Barcode -> v.value
        is FfiFieldValue.Location -> v.value.address ?: v.value.label
        is FfiFieldValue.Passkey -> "${v.value.userName} (${v.value.rpId})"
        is FfiFieldValue.File -> v.value.name
        else -> null
    }?.takeIf { it.isNotEmpty() }

    private fun copy(value: String, secret: Boolean) {
        val cm = getSystemService(ClipboardManager::class.java)
        val clip = ClipData.newPlainText("OnePass", value)
        if (secret && Build.VERSION.SDK_INT >= 33) {
            clip.description.extras = PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) }
        }
        cm.setPrimaryClip(clip)
        toast(getString(if (secret) R.string.copied_secret else R.string.copied))
        if (secret) {
            main.postDelayed({
                val now = runCatching { cm.primaryClip?.getItemAt(0)?.text?.toString() }.getOrNull()
                if (now == value) cm.clearPrimaryClip()
            }, 90_000)
        }
    }

    private fun detailScreen(vaultId: String, itemId: String) {
        val s = session() ?: return
        background({ s.item(vaultId, itemId) }) { r ->
            r.onSuccess { renderDetail(it) }.onFailure { toast(message(it)); listScreen() }
        }
    }

    private fun backBar(title: String, onBack: () -> Unit, vararg actions: Pair<String, () -> Unit>) =
        LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(4), dp(8), dp(8), dp(8))
            addView(TextView(this@MainActivity).apply {
                text = "‹"
                textSize = 30f
                setTextColor(c.accent)
                gravity = Gravity.CENTER
                minWidth = dp(48); minHeight = dp(48)
                contentDescription = "Back"
                setOnClickListener { onBack() }
            })
            addView(text(title, 18f, bold = true).apply { maxLines = 1 }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            for ((label, action) in actions) {
                addView(TextView(this@MainActivity).apply {
                    text = label
                    textSize = 15f
                    setTextColor(c.accent)
                    gravity = Gravity.CENTER
                    setPadding(dp(10), 0, dp(10), 0)
                    minHeight = dp(48)
                    setOnClickListener { action() }
                })
            }
        }

    private fun renderDetail(item: FfiItem) {
        val s = vault.session ?: return route()
        val page = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        page.addView(backBar(
            "", { listScreen() },
            (if (item.favorite) "★" else "☆") to {
                background({ s.setFavorite(item.vaultId, item.id, !item.favorite) }) { detailScreen(item.vaultId, item.id) }
            },
            getString(R.string.edit) to { editScreen(item) },
        ))
        val col = column(16)
        val header = LinearLayout(this).apply { gravity = Gravity.CENTER_VERTICAL }
        header.addView(TextView(this).apply {
            text = (item.title.trim().firstOrNull() ?: '?').uppercase()
            textSize = 22f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(c.accent)
            gravity = Gravity.CENTER
            background = rounded(Color.argb(40, Color.red(c.accent), Color.green(c.accent), Color.blue(c.accent)), 12)
        }, LinearLayout.LayoutParams(dp(54), dp(54)).apply { marginEnd = dp(14) })
        val names = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        names.addView(text(item.title.ifBlank { getString(R.string.untitled) }, 22f, bold = true))
        names.addView(text(typeLabel(item.itemType), 14f, c.ink2))
        header.addView(names)
        col.add(header)

        val pending = mutableListOf<Runnable>()

        fun card(): LinearLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = rounded(c.panel, 14, c.line)
        }

        fun row(label: String, value: String?, secret: Boolean, otp: Boolean, raw: () -> String?): View {
            val r = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding(dp(14), dp(10), dp(8), dp(10))
            }
            val texts = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
            texts.addView(text(label, 13f, c.ink2))
            val v = text(if (secret && !otp) "••••••••••" else (value ?: ""), 16f)
            if (secret) v.typeface = Typeface.MONOSPACE
            texts.addView(v)
            r.addView(texts, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            fun small(label2: String, onClick: (TextView) -> Unit) = TextView(this).apply {
                text = label2
                textSize = 14f
                setTextColor(c.accent)
                setPadding(dp(10), dp(8), dp(10), dp(8))
                setOnClickListener { onClick(this) }
            }
            if (otp) {
                val tick = object : Runnable {
                    override fun run() {
                        val secretValue = raw()
                        if (secretValue == null) {
                            v.text = getString(R.string.code_unavailable)
                        } else {
                            runCatching { totpNow(secretValue, (System.currentTimeMillis() / 1000).toULong()) }
                                .onSuccess { code -> v.text = "${code.code.take(3)} ${code.code.drop(3)}  ·  ${code.remaining}s" }
                                .onFailure { v.text = getString(R.string.code_unavailable) }
                        }
                        main.postDelayed(this, 1000)
                    }
                }
                pending.add(tick)
                r.addView(small(getString(R.string.copy)) {
                    raw()?.let { sv -> runCatching { totpNow(sv, (System.currentTimeMillis() / 1000).toULong()).code }.getOrNull() }?.let { code -> copy(code, true) }
                })
            } else {
                if (secret) {
                    var shown = false
                    r.addView(small(getString(R.string.show)) { b ->
                        shown = !shown
                        v.text = if (shown) raw() ?: "" else "••••••••••"
                        b.text = getString(if (shown) R.string.hide else R.string.show)
                    })
                }
                r.addView(small(getString(R.string.copy)) { raw()?.let { copy(it, secret) } })
            }
            return r
        }

        if (item.urls.isNotEmpty()) {
            val cd = card()
            for (u in item.urls) cd.addView(row(u.label.ifBlank { getString(R.string.website) }, u.url, false, false) { u.url })
            col.add(cd, 16)
        }
        for (section in item.sections) {
            val fields = section.fields.filter { it.value !is FfiFieldValue.Empty && display(it.value) != null }
            if (fields.isEmpty()) continue
            val cd = card()
            if (section.label.isNotBlank()) cd.addView(text(section.label, 13f, c.ink2).apply { setPadding(dp(14), dp(10), dp(14), 0) })
            for (f in fields) {
                val secret = isSecret(f.kind)
                val fieldId = f.id
                // The value is read again from the core when asked, never kept on screen.
                val raw = {
                    runCatching {
                        vault.session?.item(item.vaultId, item.id)?.sections?.flatMap { it.fields }?.firstOrNull { it.id == fieldId }?.let { display(it.value) }
                    }.getOrNull()
                }
                cd.addView(row(f.label, if (secret) null else display(f.value), secret, f.kind == FfiFieldType.OTP, raw))
            }
            col.add(cd, 16)
        }
        if (item.notes.isNotBlank()) {
            val cd = card()
            cd.addView(row(getString(R.string.notes), item.notes, false, false) { item.notes })
            col.add(cd, 16)
        }
        val df = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT)
        col.add(text(getString(R.string.modified_on, df.format(Date(item.updatedAt * 1000)), DateFormat.getDateInstance().format(Date(item.createdAt * 1000))), 12f, c.ink2), 16)
        if (item.trashedAt == null) {
            col.add(button(getString(R.string.move_to_trash)) {
                AlertDialog.Builder(this)
                    .setMessage(getString(R.string.trash_confirm, item.title))
                    .setPositiveButton(R.string.move_to_trash) { _, _ ->
                        background({ s.trashItem(item.vaultId, item.id) }) {
                            VaultWifi.changed(wifi)
                            listScreen()
                        }
                    }
                    .setNegativeButton(R.string.cancel, null)
                    .show()
            }.apply { setTextColor(c.danger) }, 24)
        }
        page.addView(scroll(col), LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        show(page) { listScreen() }
        // show() stopped the previous screen's ticks; this screen's start now.
        pending.forEach { ticks.add(it); main.post(it) }
    }

    // ---- new and edit ----------------------------------------------------------------------------------

    private fun newItemDialog() {
        val s = session() ?: return
        background({ s.vaults() }) { r ->
            val vaults: List<FfiVault> = r.getOrElse { toast(message(it)); return@background }
            val col = column(20)
            val typeSpinner = Spinner(this).apply {
                adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_dropdown_item, types.map { it.label })
            }
            val vaultSpinner = Spinner(this).apply {
                adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_dropdown_item, vaults.map { it.meta.name })
            }
            val title = field(getString(R.string.title))
            col.add(text(getString(R.string.item_type), 13f, c.ink2))
            col.add(typeSpinner)
            col.add(text(getString(R.string.vault), 13f, c.ink2), 12)
            col.add(vaultSpinner)
            col.add(title, 12)
            AlertDialog.Builder(this)
                .setTitle(R.string.new_item)
                .setView(col)
                .setPositiveButton(R.string.continue_label) { _, _ ->
                    val t = types[typeSpinner.selectedItemPosition]
                    val v = vaults[vaultSpinner.selectedItemPosition]
                    val name = title.text.toString().trim().ifEmpty { t.label }
                    // Not stored until the editor saves it: an empty item would
                    // not pass the core's validation (required fields).
                    background({ s.newItem(v.id, t.itemType, name) }) { res ->
                        res.onSuccess { editScreen(it, isNew = true) }.onFailure { toast(message(it)) }
                    }
                }
                .setNegativeButton(R.string.cancel, null)
                .show()
        }
    }

    private val textKinds = setOf(
        FfiFieldType.TEXT, FfiFieldType.CONCEALED, FfiFieldType.PASSWORD, FfiFieldType.URL, FfiFieldType.EMAIL,
        FfiFieldType.PHONE, FfiFieldType.MENU, FfiFieldType.OTP, FfiFieldType.MNEMONIC,
    )

    private fun textValue(kind: FfiFieldType, text: String): FfiFieldValue = if (text.isEmpty()) FfiFieldValue.Empty else when (kind) {
        FfiFieldType.TEXT -> FfiFieldValue.Text(text)
        FfiFieldType.CONCEALED -> FfiFieldValue.Concealed(text)
        FfiFieldType.PASSWORD -> FfiFieldValue.Password(text)
        FfiFieldType.URL -> FfiFieldValue.Url(text)
        FfiFieldType.EMAIL -> FfiFieldValue.Email(text)
        FfiFieldType.PHONE -> FfiFieldValue.Phone(text)
        FfiFieldType.MENU -> FfiFieldValue.Menu(text)
        FfiFieldType.OTP -> FfiFieldValue.Otp(text)
        else -> FfiFieldValue.Mnemonic(text)
    }

    private fun editScreen(item: FfiItem, isNew: Boolean = false) {
        val s = vault.session ?: return route()
        val page = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val col = column(16)
        val title = field(getString(R.string.title), value = item.title)
        val url = field(getString(R.string.website), value = item.urls.firstOrNull { it.primary }?.url ?: item.urls.firstOrNull()?.url ?: "").apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
        }
        col.add(text(getString(R.string.title), 13f, c.ink2))
        col.add(title, 4)
        col.add(text(getString(R.string.website), 13f, c.ink2), 12)
        col.add(url, 4)
        val inputs = mutableMapOf<String, Pair<FfiFieldType, EditText>>()
        val changed = mutableSetOf<String>()
        for (f in item.sections.flatMap { it.fields }) {
            if (f.kind !in textKinds) continue
            val secret = isSecret(f.kind)
            val has = f.value !is FfiFieldValue.Empty
            val input = field(if (secret && has) getString(R.string.unchanged) else f.label, password = secret, value = if (secret) "" else display(f.value) ?: "")
            input.addTextChangedListener(object : TextWatcher {
                override fun afterTextChanged(e: Editable?) { changed.add(f.id) }
                override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, d: Int) {}
                override fun onTextChanged(s: CharSequence?, a: Int, b: Int, d: Int) {}
            })
            inputs[f.id] = f.kind to input
            col.add(text(f.label, 13f, c.ink2), 12)
            if (f.kind == FfiFieldType.PASSWORD) {
                val line = LinearLayout(this).apply { gravity = Gravity.CENTER_VERTICAL }
                line.addView(input, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
                line.addView(TextView(this).apply {
                    text = getString(R.string.generate)
                    setTextColor(c.accent)
                    textSize = 14f
                    setPadding(dp(12), dp(12), dp(4), dp(12))
                    setOnClickListener {
                        val p = generatePassword(FfiPasswordRecipe.Characters(20u, true, true, false))
                        input.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
                        input.setText(p)
                    }
                })
                col.add(line, 4)
            } else {
                col.add(input, 4)
            }
        }
        val notes = field(getString(R.string.notes), value = item.notes).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE
            minLines = 3
            gravity = Gravity.TOP
        }
        col.add(text(getString(R.string.notes), 13f, c.ink2), 12)
        col.add(notes, 4)
        val err = text("", 14f, c.danger)
        col.add(err, 8)
        val save = {
            val updated = item.copy(
                title = title.text.toString(),
                notes = notes.text.toString(),
                urls = url.text.toString().trim().let { u ->
                    val others = item.urls.filter { !it.primary }
                    if (u.isEmpty()) others else listOf(FfiUrl("", u, FfiMatchRule.DOMAIN, true)) + others
                },
                sections = item.sections.map { sec ->
                    sec.copy(fields = sec.fields.map { f ->
                        val input = inputs[f.id]
                        if (input != null && f.id in changed) f.copy(value = textValue(f.kind, input.second.text.toString())) else f
                    })
                },
            )
            background({ s.saveItem(updated) }) { r ->
                r.onSuccess {
                    VaultWifi.changed(wifi)
                    toast(getString(R.string.saved))
                    renderDetail(it)
                }.onFailure { err.text = message(it) }
            }
        }
        val back = { if (isNew) listScreen() else detailScreen(item.vaultId, item.id) }
        page.addView(backBar(getString(if (isNew) R.string.new_item else R.string.edit), back, getString(R.string.save) to { save() }))
        page.addView(scroll(col), LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        show(page, back)
        title.requestFocus()
    }

    // ---- generator ------------------------------------------------------------------------------------------

    private fun generatorDialog(into: EditText?) {
        val col = column(20)
        val words = CheckBox(this).apply { text = getString(R.string.passphrase); setTextColor(c.ink) }
        val symbols = CheckBox(this).apply { text = getString(R.string.symbols); isChecked = true; setTextColor(c.ink) }
        val lenLabel = text("", 14f, c.ink2)
        val len = SeekBar(this).apply { max = 56; progress = 12 }
        val out = text("", 18f).apply {
            typeface = Typeface.MONOSPACE
            background = rounded(c.panel, 10, c.line)
            setPadding(dp(14), dp(14), dp(14), dp(14))
        }
        val bits = text("", 13f, c.ink2)
        fun regen() {
            val n = len.progress + 8
            lenLabel.text = getString(R.string.length, n)
            val recipe = if (words.isChecked) {
                FfiPasswordRecipe.Words(maxOf(4, n / 5).toUInt(), "-", true, true)
            } else {
                FfiPasswordRecipe.Characters(n.toUInt(), true, symbols.isChecked, false)
            }
            runCatching { generatePassword(recipe) }.onSuccess {
                out.text = it
                bits.text = getString(R.string.entropy, passwordEntropyBits(recipe).toInt())
            }.onFailure { out.text = message(it) }
        }
        words.setOnCheckedChangeListener { _, _ -> regen() }
        symbols.setOnCheckedChangeListener { _, _ -> regen() }
        len.setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
            override fun onProgressChanged(sb: SeekBar?, p: Int, user: Boolean) = regen()
            override fun onStartTrackingTouch(sb: SeekBar?) {}
            override fun onStopTrackingTouch(sb: SeekBar?) {}
        })
        col.add(words); col.add(symbols)
        col.add(lenLabel, 8); col.add(len)
        col.add(out, 12); col.add(bits, 6)
        regen()
        AlertDialog.Builder(this)
            .setTitle(R.string.generator)
            .setView(col)
            .setPositiveButton(R.string.copy) { _, _ -> copy(out.text.toString(), true) }
            .setNeutralButton(R.string.new_value, null)
            .setNegativeButton(R.string.close, null)
            .show()
            .also { d -> d.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener { regen() } }
    }

    // ---- settings ----------------------------------------------------------------------------------------------

    private fun settingsScreen() {
        val page = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        page.addView(backBar(getString(R.string.settings_title), { listScreen() }))
        val col = column(20)
        val sw = Switch(this).apply {
            text = getString(R.string.wifi_auto_title)
            textSize = 17f
            setTextColor(c.ink)
            isChecked = wifi.enabled
            minHeight = dp(48)
            setOnCheckedChangeListener { _, on -> wifi.enabled = on }
        }
        val status = text("", 14f, c.ink2)
        col.add(sw)
        col.add(status, 4)
        col.add(text(getString(R.string.security_title), 17f, bold = true), 28)
        val sec = text("", 14f, c.ink2)
        col.add(sec, 4)
        val debuggable = applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        background({ vault.protection }) { r ->
            sec.text = getString(R.string.security_body, r.getOrDefault("Android Keystore")) +
                if (debuggable) "\n" + getString(R.string.security_debug) else ""
        }
        col.add(button(getString(R.string.lock)) { lockNow() }, 28)
        page.addView(scroll(col), LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        show(page) { listScreen() }
        fun render(report: SyncReport?) {
            status.setOnClickListener(null)
            status.text = when {
                report == null -> getString(R.string.wifi_auto_idle)
                !report.enabled -> getString(R.string.wifi_auto_off)
                report.failure != null -> getString(R.string.wifi_auto_failed, report.failure)
                report.installed == 0 -> getString(R.string.wifi_auto_none)
                report.approval == SuggestionApproval.REJECTED -> {
                    status.setOnClickListener {
                        startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", packageName, null)))
                    }
                    getString(R.string.wifi_auto_rejected)
                }
                report.approval == SuggestionApproval.PENDING ->
                    resources.getQuantityString(R.plurals.wifi_auto_installed, report.installed, report.installed) + "\n" + getString(R.string.wifi_auto_pending)
                else -> resources.getQuantityString(R.plurals.wifi_auto_installed, report.installed, report.installed)
            }
        }
        val attach = {
            wifi.onReport = { r: SyncReport -> render(r) }
            render(wifi.lastReport)
            wifi.refresh()
        }
        settingsAttach = attach
        attach()
    }

    /** Re-attaches the settings screen to the Wi-Fi reports after a pause
     *  (Android's own "allow suggestions" dialog pauses the activity). */
    private var settingsAttach: (() -> Unit)? = null

    override fun onResume() {
        super.onResume()
        settingsAttach?.invoke()
    }

    override fun onPause() {
        wifi.onReport = null
        super.onPause()
    }
}
