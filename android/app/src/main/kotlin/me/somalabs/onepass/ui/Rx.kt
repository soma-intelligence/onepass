package me.somalabs.onepass.ui

import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.HorizontalScrollView
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import me.somalabs.onepass.EDGE
import me.somalabs.onepass.EDGE_ON_DARK
import me.somalabs.onepass.MainActivity
import me.somalabs.onepass.R

/*
 * The RX pages and components of the iPhone app (DesignKit `RXComponents.swift`, `RXArt.swift`,
 * Penpot "iPhone · Home", "Item", "Watchtower", "Settings"), in plain Android views.
 */

private const val MATCH = ViewGroup.LayoutParams.MATCH_PARENT
private const val WRAP = ViewGroup.LayoutParams.WRAP_CONTENT

/** The hero art of each RX screen (RXHero): the light appearance takes the airy art on Accueil. */
object RxArt {
    fun home(ui: Ios) = if (ui.dark) R.drawable.rx_hero_home else R.drawable.rx_hero_item
    val item = R.drawable.rx_hero_item
    val watchtower = R.drawable.rx_hero_watch
    val settings = R.drawable.rx_hero_settings
}

/**
 * A photo hero page (Accueil, the profile): the photo under the status bar behind `hero`, then the
 * page sheet (rounded top, radius.sheet) that scrolls over it while the hero fades.
 * `darkPhoto`: the words over the photo are white and the status bar icons light.
 */
fun MainActivity.heroPage(photo: Int, darkPhoto: Boolean, hero: LinearLayout.() -> Unit, sheet: LinearLayout.() -> Unit): View {
    val frame = FrameLayout(this).apply {
        tag = if (darkPhoto) EDGE_ON_DARK else EDGE
        setBackgroundColor(ui.page)
    }
    val art = FrameLayout(this)
    art.addView(ImageView(this).apply {
        setImageResource(photo)
        scaleType = ImageView.ScaleType.CENTER_CROP
        importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
    }, FrameLayout.LayoutParams(MATCH, MATCH))
    // Light art: a white veil keeps the dark words at their contrast (RX.Veil.lightHero).
    if (!darkPhoto) art.addView(View(this).apply {
        background = GradientDrawable(GradientDrawable.Orientation.TOP_BOTTOM, intArrayOf(Color.argb(0x26, 255, 255, 255), Color.argb(0x4D, 255, 255, 255), Color.argb(0x8C, 255, 255, 255)))
    }, FrameLayout.LayoutParams(MATCH, MATCH))
    frame.addView(art, FrameLayout.LayoutParams(MATCH, ui.dp(560) + statusTop))

    val col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    val heroCol = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(ui.dp(16), statusTop + ui.dp(8), ui.dp(16), ui.dp(28))
        hero()
    }
    col.addView(heroCol)
    val sheetCol = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        background = GradientDrawable().apply {
            setColor(ui.page)
            val r = ui.dp(Ios.Radius.SHEET).toFloat()
            cornerRadii = floatArrayOf(r, r, r, r, 0f, 0f, 0f, 0f)
        }
        setPadding(0, ui.dp(20), 0, ui.dp(120))
        minimumHeight = resources.displayMetrics.heightPixels - statusTop
        sheet()
    }
    col.addView(sheetCol)
    val scroll = ScrollView(this).apply {
        isFillViewport = true
        isVerticalScrollBarEnabled = false
        addView(col)
        setOnScrollChangeListener { _, _, y, _, _ ->
            val h = heroCol.height.coerceAtLeast(1)
            heroCol.alpha = (1f - y / (h * 0.7f)).coerceIn(0f, 1f)
            art.translationY = -y * 0.45f
        }
    }
    frame.addView(scroll, FrameLayout.LayoutParams(MATCH, MATCH))
    return frame
}

/**
 * A page with the screen's art fading into the page at its top (RXBackdrop: Watchtower, an item):
 * lighter in the light appearance so dark words keep their contrast. It moves with the page.
 * `bar` stays on top (the back button, the glass actions); `content` scrolls under it.
 */
fun MainActivity.backdropPage(photo: Int, bar: View?, content: LinearLayout.() -> Unit): View {
    val art = FrameLayout(this)
    art.addView(ImageView(this).apply {
        setImageResource(photo)
        scaleType = ImageView.ScaleType.CENTER_CROP
        alpha = if (ui.dark) 0.8f else 0.45f
        importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
    }, FrameLayout.LayoutParams(MATCH, MATCH))
    val p = ui.page
    art.addView(View(this).apply {
        background = GradientDrawable(GradientDrawable.Orientation.TOP_BOTTOM,
            intArrayOf(Color.argb(0, Color.red(p), Color.green(p), Color.blue(p)), Color.argb(0x66, Color.red(p), Color.green(p), Color.blue(p)), p))
    }, FrameLayout.LayoutParams(MATCH, MATCH))
    return backdropFrame(art, ui.dp(380) + statusTop, bar, content)
}

/**
 * An item's page: its identity color washes in from the top corners (IdentityTint.wash), in a box
 * 58% of the screen tall, fixed under the content like the iPhone's (not moving with the page).
 */
fun MainActivity.washPage(color: Int, bar: View?, content: LinearLayout.() -> Unit): View {
    val wash = View(this).apply {
        background = IdentityTint.wash(color, ui.dark)
        importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
    }
    return backdropFrame(wash, (resources.displayMetrics.heightPixels * 0.58f).toInt(), bar, content, moves = false)
}

private fun MainActivity.backdropFrame(art: View, height: Int, bar: View?, content: LinearLayout.() -> Unit, moves: Boolean = true): View {
    val frame = FrameLayout(this).apply { tag = EDGE; setBackgroundColor(ui.page) }
    frame.addView(art, FrameLayout.LayoutParams(MATCH, height))
    val barHeight = if (bar != null) ui.dp(60) else 0
    val col = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(0, statusTop + barHeight, 0, ui.dp(120))
        content()
    }
    frame.addView(ScrollView(this).apply {
        isFillViewport = true
        isVerticalScrollBarEnabled = false
        addView(col)
        if (moves) setOnScrollChangeListener { _, _, y, _, _ -> art.translationY = -y.toFloat() }
    }, FrameLayout.LayoutParams(MATCH, MATCH))
    bar?.let {
        frame.addView(it, FrameLayout.LayoutParams(MATCH, WRAP, Gravity.TOP).apply { topMargin = statusTop })
    }
    return frame
}

/** The floating bar of a pushed RX page: a glass back circle, then the actions in a glass pill. */
fun MainActivity.rxBar(trailing: List<View>, back: (() -> Unit)? = { pop() }): View {
    val bar = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        setPadding(ui.dp(16), ui.dp(8), ui.dp(16), ui.dp(8))
    }
    if (back != null) bar.addView(ui.roundButton(R.drawable.ic_chevron_left, t("Retour", "Back")) { back() }.apply {
        (getChildAt(0) as ImageView).imageTintList = android.content.res.ColorStateList.valueOf(ui.label)
    })
    bar.addView(View(this), LinearLayout.LayoutParams(0, 1, 1f))
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
    }
    return bar
}

// ---- components ----------------------------------------------------------------------------------------

/** RXCard: a borderless card of radius.card on the page, with the side gutter. */
fun Ios.rxCard(build: LinearLayout.() -> Unit): View {
    val card = LinearLayout(context).apply {
        orientation = LinearLayout.VERTICAL
        background = rounded(card, Ios.Radius.CARD)
        clipToOutline = true
        setPadding(0, 0, 0, dp(Ios.Space.S))
        build()
    }
    return inset(card, top = 0, bottom = Ios.Space.L)
}

/** RXCardHeader: the card's title (Title typography) and an optional trailing link. */
fun Ios.rxCardHeader(title: String, trailing: View? = null): View = LinearLayout(context).apply {
    gravity = Gravity.CENTER_VERTICAL
    setPadding(dp(20), dp(18), dp(12), dp(6))
    addView(text(title, 22f, label, 600).apply { maxLines = 2 }, LinearLayout.LayoutParams(0, WRAP, 1f))
    trailing?.let { addView(it) }
}

/** RXCardMessage: a quiet line in a card with nothing to list. */
fun Ios.rxMessage(s: String): View = text(s, 15f, secondary).apply { setPadding(dp(20), dp(4), dp(20), dp(12)) }

/** An accent text link in a card header ("Tout voir"). */
fun Ios.rxLink(s: String, onClick: () -> Unit): View = text(s, 15f, readableAccent, 500).apply {
    setPadding(dp(8), dp(10), dp(8), dp(10))
    isClickable = true
    setOnClickListener { onClick() }
}

/** RXItemRow: the leading art, the title (Body medium), the subtitle, a value, a chevron. */
fun Ios.rxRow(lead: View?, title: String, subtitle: String? = null, value: String? = null, chevron: Boolean = false, onClick: (() -> Unit)? = null): LinearLayout =
    row(icon = lead, title = title, subtitle = subtitle, value = value, chevron = chevron, minHeightDp = 64, onClick = onClick).apply {
        setPadding(dp(20), dp(Ios.Space.S + 2), dp(16), dp(Ios.Space.S + 2))
    }

/** A coloured disc with a white glyph (Watchtower tiles and rows, the vaults). */
fun Ios.disc(res: Int, color: Int, sizeDp: Int = 40) = FrameLayout(context).apply {
    background = GradientDrawable().apply { shape = GradientDrawable.OVAL; setColor(color) }
    layoutParams = LinearLayout.LayoutParams(dp(sizeDp), dp(sizeDp))
    val g = (sizeDp * 0.5f).toInt()
    addView(glyph(res, Color.WHITE, g), FrameLayout.LayoutParams(dp(g), dp(g), Gravity.CENTER))
}

/**
 * QuickActionLabel: a 60 dp disc and its label under it. Over a dark photo the disc is glass and
 * the glyph white; elsewhere a white (or raised) disc with the accent glyph.
 */
fun Ios.quickAction(icon: Int, label: String, onPhoto: Boolean, enabled: Boolean = true, onClick: () -> Unit): View = LinearLayout(context).apply {
    orientation = LinearLayout.VERTICAL
    gravity = Gravity.CENTER_HORIZONTAL
    contentDescription = label
    isClickable = enabled
    alpha = if (enabled) 1f else 0.45f
    setOnClickListener { onClick() }
    val discColor = when {
        onPhoto -> Color.argb(0x33, 0xFF, 0xFF, 0xFF)
        dark -> raised
        else -> Color.WHITE
    }
    val disc = FrameLayout(context).apply {
        background = GradientDrawable().apply {
            shape = GradientDrawable.OVAL
            setColor(discColor)
            if (onPhoto) setStroke(maxOf(1, dp(0.5)), Color.argb(0x33, 255, 255, 255))
        }
        if (!onPhoto && !dark) elevation = dp(2).toFloat()
        addView(glyph(icon, if (onPhoto) Color.WHITE else readableAccent, 26), FrameLayout.LayoutParams(dp(26), dp(26), Gravity.CENTER))
    }
    addView(disc, LinearLayout.LayoutParams(dp(60), dp(60)))
    addView(text(label, 15f, if (onPhoto) Color.WHITE else this@quickAction.label, 500).apply {
        gravity = Gravity.CENTER
        maxLines = 1
        setPadding(0, dp(8), 0, 0)
    })
}

/** A row of quick actions sharing the width (QuickActionRow). */
fun Ios.quickActionRow(vararg actions: View): View = LinearLayout(context).apply {
    orientation = LinearLayout.HORIZONTAL
    actions.forEach { addView(it, LinearLayout.LayoutParams(0, WRAP, 1f)) }
}

/** A glass capsule holding a glyph and words (the score chip, the vault chip). */
fun Ios.glassChip(lead: View?, words: String, onPhoto: Boolean): View = LinearLayout(context).apply {
    gravity = Gravity.CENTER_VERTICAL
    background = rounded(if (onPhoto) Color.argb(0x33, 0xFF, 0xFF, 0xFF) else glass, 999, if (onPhoto) Color.argb(0x33, 255, 255, 255) else hairline)
    setPadding(dp(Ios.Space.M), dp(7), dp(Ios.Space.L), dp(7))
    lead?.let {
        addView(it, (it.layoutParams as? LinearLayout.LayoutParams ?: LinearLayout.LayoutParams(dp(20), dp(20))).apply { marginEnd = dp(Ios.Space.S) })
    }
    addView(text(words, 15f, if (onPhoto) Color.WHITE else label, 600).apply { maxLines = 1; fontFeatureSettings = "tnum" })
}

/** RXCarousel: tiles in a row that scrolls sideways, the next one peeking. */
fun Ios.carousel(tiles: List<View>): View {
    val row = LinearLayout(context).apply { setPadding(dp(12), dp(4), dp(12), dp(14)) }
    tiles.forEach { row.addView(it, LinearLayout.LayoutParams(dp(96), WRAP).apply { marginEnd = dp(Ios.Space.S) }) }
    return HorizontalScrollView(context).apply {
        isHorizontalScrollBarEnabled = false
        clipToPadding = false
        addView(row)
    }
}

/** RXFavoriteTile: the item's art over its title on two lines. */
fun Ios.favoriteTile(art: View, title: String, onClick: () -> Unit): View = LinearLayout(context).apply {
    orientation = LinearLayout.VERTICAL
    gravity = Gravity.CENTER_HORIZONTAL
    background = pressable(null, Ios.Radius.TILE)
    setPadding(0, dp(6), 0, dp(6))
    isClickable = true
    contentDescription = title
    setOnClickListener { onClick() }
    addView(art)
    addView(text(title, 15f, label).apply {
        gravity = Gravity.CENTER
        maxLines = 2
        ellipsize = android.text.TextUtils.TruncateAt.END
        setPadding(dp(2), dp(10), dp(2), 0)
    }, LinearLayout.LayoutParams(MATCH, WRAP))
}
