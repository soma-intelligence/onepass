package me.somalabs.onepass.ui

import android.content.Context
import android.content.res.ColorStateList
import android.content.res.Configuration
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.Drawable
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.RippleDrawable
import android.text.InputType
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.Switch
import android.widget.TextView
import me.somalabs.onepass.R

/**
 * The RX look of the iPhone app (DesignKit `RXTokens+Generated.swift`, from Penpot) in plain
 * Android views: the page (#F2F2F7 / black), borderless cards of radius 24 (#FFFFFF / #161618),
 * the indigo accent #5856D6 with its lighter text tone in dark mode, the RX semantic colours
 * (positive, negative, warning), glass for controls over a photo, Inter for every word, and the
 * 4 to 32 spacing scale.
 */
class Ios(val context: Context) {
    val dark = context.resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK == Configuration.UI_MODE_NIGHT_YES

    private fun tone(light: Int, dark: Int) = if (this.dark) dark else light

    // RX colour tokens (bg.*, text.*, accent.*, separator, tab.*).
    val page = tone(Color.rgb(0xF2, 0xF2, 0xF7), Color.BLACK)
    val card = tone(Color.WHITE, Color.rgb(0x16, 0x16, 0x18))
    val raised = tone(Color.WHITE, Color.rgb(0x2C, 0x2C, 0x2E))
    /** bg.field: inputs, tracks, the inactive segment. */
    val fill = tone(Color.rgb(0xE9, 0xE9, 0xEE), Color.rgb(0x1F, 0x1F, 0x22))
    /** bg.glass: a control over the page or a photo. */
    val glass = tone(Color.argb(0xB8, 0xFF, 0xFF, 0xFF), Color.argb(0x3D, 0x76, 0x76, 0x80))
    val label = tone(Color.rgb(0x0B, 0x0B, 0x0F), Color.WHITE)
    val secondary = tone(Color.rgb(0x6B, 0x6B, 0x73), Color.rgb(0xA1, 0xA1, 0xA6))
    val tertiary = tone(Color.rgb(0xA0, 0xA0, 0xA8), Color.rgb(0x6E, 0x6E, 0x73))
    val separator = tone(Color.rgb(0xE3, 0xE3, 0xE8), Color.rgb(0x2A, 0x2A, 0x2E))
    /** RX cards have no outline: kept for the few controls drawn over a photo. */
    val hairline = tone(Color.argb(0x0F, 0, 0, 0), Color.argb(0x14, 0xFF, 0xFF, 0xFF))
    val accent = Color.rgb(0x58, 0x56, 0xD6)
    /** accent.text: accent for words, 4.5:1 on the page in both appearances. */
    val readableAccent = tone(accent, Color.rgb(0xA3, 0xA2, 0xE8))
    /** accent.soft: a tinted chip or the selected row. */
    val accentSoft = tone(Color.argb(0x1F, 0x58, 0x56, 0xD6), Color.argb(0x2E, 0xA3, 0xA2, 0xE8))
    /** tab.bar, more opaque than on iPhone: Android draws no blur under it. */
    val tabBar = tone(Color.argb(0xF5, 0xFF, 0xFF, 0xFF), Color.argb(0xF2, 0x2C, 0x2C, 0x2E))
    val tabActive = tone(Color.argb(0x14, 0x0B, 0x0B, 0x0F), Color.argb(0x24, 0xFF, 0xFF, 0xFF))
    /** negative, warning, positive. */
    val red = tone(Color.rgb(0xE5, 0x48, 0x4D), Color.rgb(0xFF, 0x5B, 0x61))
    val orange = tone(Color.rgb(0xE3, 0x9A, 0x00), Color.rgb(0xFF, 0xB0, 0x20))
    val green = tone(Color.rgb(0x11, 0xA8, 0x66), Color.rgb(0x3F, 0xD6, 0x8F))
    val yellow = tone(Color.rgb(0xFF, 0xCC, 0x00), Color.rgb(0xFF, 0xD6, 0x0A))
    val teal = tone(Color.rgb(0x13, 0xA0, 0x9A), Color.rgb(0x40, 0xCB, 0xC0))
    val blue = tone(Color.rgb(0x2F, 0x80, 0xED), Color.rgb(0x4A, 0x9B, 0xFF))
    val purple = tone(Color.rgb(0x8E, 0x4E, 0xC6), Color.rgb(0xA8, 0x6B, 0xE0))
    val amberStar = Color.rgb(0xFF, 0x9F, 0x0A)

    // Spacing (space.*) and radii (radius.*), in dp.
    object Space { const val XXS = 2; const val XS = 4; const val S = 8; const val M = 12; const val L = 16; const val XL = 24; const val XXL = 32 }
    object Radius { const val CHIP = 12; const val CONTROL = 12; const val TILE = 16; const val CARD = 24; const val SHEET = 36 }

    fun dp(v: Number): Int = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v.toFloat(), context.resources.displayMetrics).toInt()

    /** Inter (the RX family) at a CSS weight, its variable axis set to it. */
    fun font(weight: Int = 400): Typeface = fonts.getOrPut(weight) {
        runCatching {
            Typeface.Builder(context.assets, "fonts/Inter.ttf").setFontVariationSettings("'wght' $weight").setWeight(weight).build()
        }.getOrNull() ?: Typeface.create(Typeface.DEFAULT, weight, false)
    }

    /** The RX tracking of a size (Penpot's letter spacing in points, here in em). */
    private fun tracking(size: Float): Float = when {
        size >= 50f -> -2f / 56f
        size >= 40f -> -1.57f / 44f
        size >= 28f -> -0.8f / 34f
        size >= 20f -> -0.3f / 22f
        size >= 16f -> -0.2f / 17f
        size >= 14f -> -0.1f / 15f
        size >= 12f -> 0f
        else -> 0.1f / 11f
    }

    fun rounded(color: Int, radiusDp: Number = Radius.CARD, stroke: Int? = null) = GradientDrawable().apply {
        setColor(color)
        cornerRadius = dp(radiusDp).toFloat()
        stroke?.let { setStroke(maxOf(1, dp(0.5)), it) }
    }

    /** A pressed state like a UITableViewCell highlight. */
    fun pressable(bg: Drawable?, radiusDp: Number = 0): Drawable =
        RippleDrawable(ColorStateList.valueOf(if (dark) Color.argb(0x33, 255, 255, 255) else Color.argb(0x1A, 0, 0, 0)), bg, rounded(Color.WHITE, radiusDp))

    // ---- text --------------------------------------------------------------------------

    fun text(s: CharSequence = "", size: Float = 17f, color: Int = label, weight: Int = 400) = TextView(context).apply {
        text = s
        textSize = size
        setTextColor(color)
        typeface = font(weight)
        letterSpacing = tracking(size)
        includeFontPadding = false
        setLineSpacing(0f, if (size >= 28f) 1.05f else 1.15f)
    }

    /** "Large Title": 34 sp bold, the root screens' title. */
    fun largeTitle(s: String) = text(s, 34f, label, 700).apply {
        setPadding(dp(Space.L), dp(Space.XS), dp(Space.L), dp(Space.S))
    }

    /** Grouped section header: secondary, a touch bold. */
    fun sectionHeader(s: String, trailing: View? = null): View {
        val row = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(Space.L + 4), dp(Space.XL), dp(Space.L + 4), dp(Space.S))
        }
        row.addView(text(s, 22f, label, 600), LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        trailing?.let { row.addView(it) }
        return row
    }

    /** Small caps section label of the item detail ("LOGIN"). */
    fun capsLabel(s: String) = text(s.uppercase(), 13f, secondary, 600).apply {
        letterSpacing = 0.08f
        setPadding(dp(Space.L + 4), dp(Space.XL - 4), dp(Space.L), dp(Space.S - 2))
    }

    fun footnote(s: String, color: Int = secondary) = text(s, 13f, color).apply {
        setPadding(dp(Space.L + 4), dp(Space.S), dp(Space.L + 4), dp(Space.XS))
    }

    // ---- icons --------------------------------------------------------------------------

    fun glyph(res: Int, color: Int = accent, sizeDp: Int = 22) = ImageView(context).apply {
        setImageResource(res)
        imageTintList = ColorStateList.valueOf(color)
        layoutParams = LinearLayout.LayoutParams(dp(sizeDp), dp(sizeDp))
    }

    fun image(res: Int, sizeDp: Int) = ImageView(context).apply {
        setImageResource(res)
        scaleType = ImageView.ScaleType.FIT_CENTER
        layoutParams = LinearLayout.LayoutParams(dp(sizeDp), dp(sizeDp))
    }

    /** A rounded colored square with a white glyph (iOS settings row tile). */
    fun symbolTile(res: Int, color: Int, sizeDp: Int = 30) = FrameLayout(context).apply {
        background = rounded(color, sizeDp * 0.23f)
        layoutParams = LinearLayout.LayoutParams(dp(sizeDp), dp(sizeDp))
        addView(glyph(res, Color.WHITE, (sizeDp * 0.6f).toInt()), FrameLayout.LayoutParams(dp(sizeDp * 0.6f), dp(sizeDp * 0.6f), Gravity.CENTER))
    }

    /** Round translucent toolbar button ("Liquid Glass" circle of the iPhone toolbar). */
    fun roundButton(res: Int, desc: String, onClick: () -> Unit) = FrameLayout(context).apply {
        background = pressable(rounded(glass, 22, hairline), 22)
        contentDescription = desc
        isClickable = true
        setOnClickListener { onClick() }
        addView(glyph(res, accent, 24), FrameLayout.LayoutParams(dp(24), dp(24), Gravity.CENTER))
        layoutParams = LinearLayout.LayoutParams(dp(44), dp(44))
    }

    // ---- grouped cards ------------------------------------------------------------------

    /** An inset grouped section: rounded card with hairline, rows separated by inset lines. */
    fun card(vararg rows: View?): LinearLayout = LinearLayout(context).apply {
        orientation = LinearLayout.VERTICAL
        background = rounded(card, Radius.CARD)
        clipToOutline = true
        val visible = rows.filterNotNull()
        visible.forEachIndexed { i, r ->
            addView(r)
            if (i < visible.lastIndex) addView(separatorLine())
        }
    }

    fun separatorLine(insetDp: Int = 60) = View(context).apply {
        setBackgroundColor(separator)
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, maxOf(1, dp(0.5))).apply { marginStart = dp(insetDp); marginEnd = dp(Space.L) }
    }

    /** Wraps a card with the side gutter. */
    fun inset(v: View, top: Int = 0, bottom: Int = 0): View = FrameLayout(context).apply {
        setPadding(dp(Space.L), dp(top), dp(Space.L), dp(bottom))
        addView(v)
    }

    /**
     * A grouped row: leading icon view, title and subtitle, trailing value, chevron.
     * `titleColor` for action rows ("Nouveau coffre" in accent, "Supprimer" in red).
     */
    fun row(
        icon: View? = null,
        title: String,
        subtitle: String? = null,
        value: String? = null,
        chevron: Boolean = true,
        titleColor: Int = label,
        trailing: View? = null,
        minHeightDp: Int = 52,
        onClick: (() -> Unit)? = null,
    ): LinearLayout = LinearLayout(context).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        minimumHeight = dp(minHeightDp)
        setPadding(dp(Space.L), dp(Space.S + 2), dp(Space.M + 2), dp(Space.S + 2))
        if (onClick != null) {
            background = pressable(null)
            isClickable = true
            setOnClickListener { onClick() }
        }
        icon?.let {
            val lp = (it.layoutParams as? LinearLayout.LayoutParams) ?: LinearLayout.LayoutParams(dp(30), dp(30))
            lp.marginEnd = dp(Space.M + 2)
            addView(it, lp)
        }
        val texts = LinearLayout(context).apply { orientation = LinearLayout.VERTICAL }
        texts.addView(text(title, 17f, titleColor, 500).apply { maxLines = 2 })
        subtitle?.takeIf { it.isNotBlank() }?.let {
            texts.addView(text(it, 15f, secondary).apply { maxLines = 1; setPadding(0, dp(3), 0, 0) })
        }
        addView(texts, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        value?.let { addView(text(it, 17f, secondary).apply { setPadding(dp(Space.S), 0, dp(Space.XS), 0) }) }
        trailing?.let { addView(it) }
        if (chevron && onClick != null) addView(glyph(R.drawable.ic_chevron_right, tertiary, 20))
    }

    /** A switch row (iOS UISwitch, green when on). */
    fun toggleRow(title: String, subtitle: String? = null, on: Boolean, onChange: (Boolean) -> Unit): LinearLayout {
        val sw = Switch(context).apply {
            isChecked = on
            thumbTintList = ColorStateList.valueOf(Color.WHITE)
            trackTintList = ColorStateList(arrayOf(intArrayOf(android.R.attr.state_checked), intArrayOf()), intArrayOf(green, if (dark) Color.rgb(0x3A, 0x3A, 0x3E) else Color.rgb(0xD5, 0xD5, 0xDB)))
            setOnCheckedChangeListener { _, v -> onChange(v) }
        }
        // Touching the row flips the switch, as on iPhone.
        return row(title = title, subtitle = subtitle, chevron = false, trailing = sw) { if (sw.isEnabled) sw.toggle() }
    }

    // ---- inputs ----------------------------------------------------------------------------

    fun field(hint: String, value: String = "", password: Boolean = false) = EditText(context).apply {
        this.hint = hint
        setText(value)
        textSize = 17f
        setTextColor(label)
        setHintTextColor(tertiary)
        background = null
        setPadding(dp(Space.L), dp(Space.M), dp(Space.L), dp(Space.M))
        inputType = if (password) InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        else InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        imeOptions = EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
        typeface = font(400)
    }

    /** The search capsule ("Titre, site, identifiant, tag"). */
    fun searchField(hint: String, value: String = "") = LinearLayout(context).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        background = rounded(fill, Radius.CHIP)
        setPadding(dp(Space.M), 0, dp(Space.S), 0)
        addView(glyph(R.drawable.ic_search, secondary, 20))
        addView(field(hint, value).apply { setPadding(dp(Space.S), dp(Space.S + 1), dp(Space.S), dp(Space.S + 1)) },
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
    }

    /** A filled capsule button (prominent) or a tinted one. */
    fun capsule(label: String, prominent: Boolean = true, color: Int = accent, onClick: () -> Unit) = TextView(context).apply {
        text = label
        textSize = 17f
        typeface = font(600)
        gravity = Gravity.CENTER
        setTextColor(if (prominent) Color.WHITE else color)
        val bg = if (prominent) color else Color.argb(if (dark) 0x40 else 0x1F, Color.red(color), Color.green(color), Color.blue(color))
        background = pressable(rounded(bg, 999), 999)
        setPadding(dp(Space.XL), dp(Space.M + 2), dp(Space.XL), dp(Space.M + 2))
        minHeight = dp(50)
        isClickable = true
        filterTouchesWhenObscured = true
        setOnClickListener { onClick() }
    }

    fun chip(caption: String, color: Int = accent) = text(caption, 15f, label, 500).apply {
        background = rounded(Color.argb(if (dark) 0x40 else 0x1F, Color.red(color), Color.green(color), Color.blue(color)), Radius.CHIP)
        setPadding(dp(Space.M), dp(Space.XS + 2), dp(Space.M), dp(Space.XS + 2))
    }

    /** Circular initials avatar (vault tile, account avatar). */
    fun monogram(letters: String, color: Int, sizeDp: Int, square: Boolean = false) = TextView(context).apply {
        text = letters
        textSize = sizeDp * 0.4f
        typeface = font(600)
        setTextColor(Color.WHITE)
        gravity = Gravity.CENTER
        background = if (square) rounded(color, sizeDp * 0.24f) else GradientDrawable().apply { shape = GradientDrawable.OVAL; setColor(color) }
        includeFontPadding = false
        layoutParams = LinearLayout.LayoutParams(dp(sizeDp), dp(sizeDp))
    }

    companion object {
        /** Inter per weight, built once for the process. */
        private val fonts = HashMap<Int, Typeface>()

        /** Vault colors of the iPhone app (vault tile palette). */
        val VAULT_COLORS = mapOf(
            "blue" to Color.rgb(0x2F, 0x80, 0xED), "teal" to Color.rgb(0x13, 0xA0, 0x9A), "orange" to Color.rgb(0xE0, 0x8A, 0x00),
            "red" to Color.rgb(0xE5, 0x48, 0x4D), "purple" to Color.rgb(0x8E, 0x4E, 0xC6), "green" to Color.rgb(0x22, 0xA0, 0x6B),
            "pink" to Color.rgb(0xDB, 0x27, 0x77), "indigo" to Color.rgb(0x58, 0x56, 0xD6), "gray" to Color.rgb(0x8E, 0x8E, 0x93),
        )

        fun vaultColor(name: String): Int = VAULT_COLORS[name] ?: VAULT_COLORS.values.elementAt((name.hashCode() and 0x7fffffff) % VAULT_COLORS.size)
    }
}
