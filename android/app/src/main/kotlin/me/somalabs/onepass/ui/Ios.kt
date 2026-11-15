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
 * The iPhone app's look in plain Android views (DesignKit `Theme`, `ThemeMetrics`):
 * the grouped page (soft gray in light, black in dark), white or raised-gray
 * cards of radius 18 with a hairline, the indigo accent #5856D6, accent labels
 * lightened in dark mode, the 2 to 32 spacing scale, large titles.
 */
class Ios(val context: Context) {
    val dark = context.resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK == Configuration.UI_MODE_NIGHT_YES

    // iOS system colors (systemGroupedBackground, secondarySystemGroupedBackground, label...).
    val page = if (dark) Color.BLACK else Color.rgb(0xF2, 0xF2, 0xF7)
    val card = if (dark) Color.rgb(0x1C, 0x1C, 0x1E) else Color.WHITE
    val raised = if (dark) Color.rgb(0x2C, 0x2C, 0x2E) else Color.rgb(0xE5, 0xE5, 0xEA)
    val fill = if (dark) Color.argb(0x5C, 0x76, 0x76, 0x80) else Color.argb(0x1F, 0x76, 0x76, 0x80)
    val label = if (dark) Color.WHITE else Color.BLACK
    val secondary = if (dark) Color.argb(0x99, 0xEB, 0xEB, 0xF5) else Color.argb(0x99, 0x3C, 0x3C, 0x43)
    val tertiary = if (dark) Color.argb(0x4D, 0xEB, 0xEB, 0xF5) else Color.argb(0x4D, 0x3C, 0x3C, 0x43)
    val separator = if (dark) Color.argb(0x99, 0x54, 0x54, 0x58) else Color.argb(0x4A, 0x3C, 0x3C, 0x43)
    val hairline = if (dark) Color.argb(0x0F, 0xFF, 0xFF, 0xFF) else Color.argb(0x0F, 0, 0, 0)
    val accent = Color.rgb(0x58, 0x56, 0xD6)
    /** Accent for small text: 4.5:1 on the page in both appearances. */
    val readableAccent = if (dark) Color.rgb(0xA3, 0xA2, 0xE8) else accent
    val red = if (dark) Color.rgb(0xFF, 0x45, 0x3A) else Color.rgb(0xFF, 0x3B, 0x30)
    val orange = if (dark) Color.rgb(0xFF, 0x9F, 0x0A) else Color.rgb(0xFF, 0x95, 0x00)
    val yellow = if (dark) Color.rgb(0xFF, 0xD6, 0x0A) else Color.rgb(0xFF, 0xCC, 0x00)
    val green = if (dark) Color.rgb(0x30, 0xD1, 0x58) else Color.rgb(0x34, 0xC7, 0x59)
    val teal = if (dark) Color.rgb(0x40, 0xCB, 0xE0) else Color.rgb(0x30, 0xB0, 0xC7)
    val blue = if (dark) Color.rgb(0x0A, 0x84, 0xFF) else Color.rgb(0x00, 0x7A, 0xFF)
    val amberStar = Color.rgb(0xFF, 0x9F, 0x0A)

    // Spacing (Theme.Space) and radii (Theme.Radius), in dp.
    object Space { const val XXS = 2; const val XS = 4; const val S = 8; const val M = 12; const val L = 16; const val XL = 24; const val XXL = 32 }
    object Radius { const val CHIP = 8; const val CONTROL = 12; const val CARD = 18; const val SHEET = 26 }

    fun dp(v: Number): Int = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v.toFloat(), context.resources.displayMetrics).toInt()

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
        typeface = Typeface.create(Typeface.DEFAULT, weight, false)
        includeFontPadding = false
        setLineSpacing(0f, 1.12f)
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
        row.addView(text(s, 20f, secondary, 600), LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        trailing?.let { row.addView(it) }
        return row
    }

    /** Small caps section label of the item detail ("LOGIN"). */
    fun capsLabel(s: String) = text(s.uppercase(), 13f, secondary, 600).apply {
        letterSpacing = 0.04f
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
        background = pressable(rounded(if (dark) Color.argb(0xCC, 0x2C, 0x2C, 0x2E) else Color.argb(0xE6, 0xFF, 0xFF, 0xFF), 22, hairline), 22)
        elevation = dp(2).toFloat()
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
        background = rounded(card, Radius.CARD, hairline)
        clipToOutline = true
        val visible = rows.filterNotNull()
        visible.forEachIndexed { i, r ->
            addView(r)
            if (i < visible.lastIndex) addView(separatorLine())
        }
    }

    fun separatorLine(insetDp: Int = 60) = View(context).apply {
        setBackgroundColor(separator)
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, maxOf(1, dp(0.33))).apply { marginStart = dp(insetDp) }
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
        texts.addView(text(title, 17f, titleColor).apply { maxLines = 2 })
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
            trackTintList = ColorStateList(arrayOf(intArrayOf(android.R.attr.state_checked), intArrayOf()), intArrayOf(green, fill))
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
        typeface = Typeface.DEFAULT
    }

    /** The search capsule ("Titre, site, identifiant, tag"). */
    fun searchField(hint: String, value: String = "") = LinearLayout(context).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        background = rounded(fill, 12)
        setPadding(dp(Space.S + 2), 0, dp(Space.S), 0)
        addView(glyph(R.drawable.ic_search, secondary, 20))
        addView(field(hint, value).apply { setPadding(dp(Space.S), dp(Space.S + 1), dp(Space.S), dp(Space.S + 1)) },
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
    }

    /** A filled capsule button (prominent) or a tinted one. */
    fun capsule(label: String, prominent: Boolean = true, color: Int = accent, onClick: () -> Unit) = TextView(context).apply {
        text = label
        textSize = 17f
        typeface = Typeface.create(Typeface.DEFAULT, 600, false)
        gravity = Gravity.CENTER
        setTextColor(if (prominent) Color.WHITE else color)
        val bg = if (prominent) color else Color.argb(if (dark) 0x40 else 0x1F, Color.red(color), Color.green(color), Color.blue(color))
        background = pressable(rounded(bg, 25), 25)
        setPadding(dp(Space.XL), dp(Space.M + 2), dp(Space.XL), dp(Space.M + 2))
        minHeight = dp(50)
        isClickable = true
        filterTouchesWhenObscured = true
        setOnClickListener { onClick() }
    }

    fun chip(caption: String, color: Int = accent) = text(caption, 15f, label, 500).apply {
        background = rounded(Color.argb(if (dark) 0x40 else 0x1F, Color.red(color), Color.green(color), Color.blue(color)), 9)
        setPadding(dp(Space.M), dp(Space.XS + 2), dp(Space.M), dp(Space.XS + 2))
    }

    /** Circular initials avatar (vault tile, account avatar). */
    fun monogram(letters: String, color: Int, sizeDp: Int, square: Boolean = false) = TextView(context).apply {
        text = letters
        textSize = sizeDp * 0.4f
        typeface = Typeface.create(Typeface.DEFAULT, 600, false)
        setTextColor(Color.WHITE)
        gravity = Gravity.CENTER
        background = if (square) rounded(color, sizeDp * 0.24f) else GradientDrawable().apply { shape = GradientDrawable.OVAL; setColor(color) }
        includeFontPadding = false
        layoutParams = LinearLayout.LayoutParams(dp(sizeDp), dp(sizeDp))
    }

    companion object {
        /** Vault colors of the iPhone app (vault tile palette). */
        val VAULT_COLORS = mapOf(
            "blue" to Color.rgb(0x2F, 0x80, 0xED), "teal" to Color.rgb(0x13, 0xA0, 0x9A), "orange" to Color.rgb(0xE0, 0x8A, 0x00),
            "red" to Color.rgb(0xE5, 0x48, 0x4D), "purple" to Color.rgb(0x8E, 0x4E, 0xC6), "green" to Color.rgb(0x22, 0xA0, 0x6B),
            "pink" to Color.rgb(0xDB, 0x27, 0x77), "indigo" to Color.rgb(0x58, 0x56, 0xD6), "gray" to Color.rgb(0x8E, 0x8E, 0x93),
        )

        fun vaultColor(name: String): Int = VAULT_COLORS[name] ?: VAULT_COLORS.values.elementAt((name.hashCode() and 0x7fffffff) % VAULT_COLORS.size)
    }
}
