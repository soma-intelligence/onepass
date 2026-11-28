package me.somalabs.onepass.ui

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.ColorFilter
import android.graphics.Matrix
import android.graphics.Paint
import android.graphics.PixelFormat
import android.graphics.RadialGradient
import android.graphics.Shader
import android.graphics.drawable.Drawable
import kotlin.math.max
import kotlin.math.min

/**
 * The identity color of an item, the tint of the wash behind its detail header: a port of
 * DesignKit's `IdentityTint` and `Theme.Wash.identityGlows` (apple/DesignKit/.../IdentityTint.swift),
 * same thresholds, same buckets, same glows.
 */
object IdentityTint {
    private const val SAMPLE_SIDE = 16
    private const val MINIMUM_SATURATION = 0.15
    private const val MINIMUM_PIXEL_SATURATION = 0.25
    private const val MINIMUM_PIXEL_BRIGHTNESS = 0.2
    private const val HUE_BUCKETS = 12

    /** Card networks' colors (ItemIcon.brandColor). */
    fun brandColor(brand: String): Int? = when (brand) {
        "visa" -> Color.rgb(0x1A, 0x1F, 0x71)
        "mastercard" -> Color.rgb(0x1C, 0x1C, 0x1E)
        "amex" -> Color.rgb(0x2E, 0x77, 0xBC)
        "discover" -> Color.rgb(0xF2, 0x65, 0x1E)
        "jcb" -> Color.rgb(0x0B, 0x4E, 0xA2)
        "diners_club" -> Color.rgb(0x00, 0x79, 0xBE)
        else -> null
    }

    /**
     * The dominant saturated color of an icon: a 16 x 16 copy, pixels with alpha above 0.5,
     * near-gray, near-black and near-white ones dropped, the rest bucketed by hue (12 buckets of
     * 30 degrees centered on 0, 30, ... 330), and the mean of the fullest bucket. Null when no
     * pixel qualifies.
     */
    fun dominant(icon: Bitmap): Int? {
        val small = Bitmap.createScaledBitmap(icon, SAMPLE_SIDE, SAMPLE_SIDE, true)
        val pixels = IntArray(SAMPLE_SIDE * SAMPLE_SIDE)
        small.getPixels(pixels, 0, SAMPLE_SIDE, 0, 0, SAMPLE_SIDE, SAMPLE_SIDE)
        if (small !== icon) small.recycle()
        val sums = Array(HUE_BUCKETS) { DoubleArray(4) }
        for (p in pixels) {
            if (Color.alpha(p) / 255.0 <= 0.5) continue
            // getPixels returns unpremultiplied components.
            val r = Color.red(p) / 255.0
            val g = Color.green(p) / 255.0
            val b = Color.blue(p) / 255.0
            val high = max(r, max(g, b))
            val chroma = high - min(r, min(g, b))
            if (high < MINIMUM_PIXEL_BRIGHTNESS || chroma / high < MINIMUM_PIXEL_SATURATION) continue
            var hue = when (high) {
                r -> (g - b) / chroma
                g -> 2 + (b - r) / chroma
                else -> 4 + (r - g) / chroma
            }
            hue = (hue * 60) % 360
            if (hue < 0) hue += 360
            val bucket = ((hue + 15) / 30).toInt() % HUE_BUCKETS
            sums[bucket][0] += r; sums[bucket][1] += g; sums[bucket][2] += b; sums[bucket][3] += 1.0
        }
        var best = 0
        for (i in 1 until HUE_BUCKETS) if (sums[i][3] > sums[best][3]) best = i
        val w = sums[best]
        if (w[3] == 0.0) return null
        return Color.rgb((w[0] / w[3] * 255).toInt(), (w[1] / w[3] * 255).toInt(), (w[2] / w[3] * 255).toInt())
    }

    /** The brand color, else the icon's dominant color, else the category color; a colorless logo takes the accent. */
    fun color(brand: String?, siteIcon: Bitmap?, category: Int, accent: Int): Int {
        brand?.let(::brandColor)?.let { return fallback(it, accent) }
        if (siteIcon == null) return fallback(category, accent)
        return dominant(siteIcon) ?: accent
    }

    /** The accent for a color too gray to tint a wash. */
    fun fallback(color: Int, accent: Int): Int {
        val r = Color.red(color); val g = Color.green(color); val b = Color.blue(color)
        val high = max(r, max(g, b)); val low = min(r, min(g, b))
        val saturation = if (high > 0) (high - low).toDouble() / high else 0.0
        return if (saturation < MINIMUM_SATURATION) accent else color
    }

    /** `color` turned `degrees` around the HSB hue wheel. */
    fun rotated(color: Int, degrees: Float): Int {
        val hsv = FloatArray(3)
        Color.colorToHSV(color, hsv)
        if (hsv[1] == 0f) return color
        hsv[0] = ((hsv[0] + degrees) % 360f + 360f) % 360f
        return Color.HSVToColor(hsv)
    }

    /** Theme.Wash.identityOpacity: the leading glow's peak (the trailing one draws at 85% of it). */
    fun peak(dark: Boolean) = if (dark) 0.28 else 0.14

    /**
     * The two glows behind an item's header (Theme.Wash.identityGlows): soft ellipses from the
     * top corners in the identity color turned -14 and +22 degrees, fading on a smoothstep curve,
     * reaching 71% of the box's width and height. Draw it in a box 58% of the screen tall.
     */
    fun wash(color: Int, dark: Boolean): Drawable = object : Drawable() {
        private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
        private val curve = floatArrayOf(0f, 0.25f, 0.5f, 0.75f, 1f)
        private val alphas = doubleArrayOf(1.0, 0.844, 0.5, 0.156, 0.0)

        private fun glow(canvas: Canvas, tint: Int, peak: Double, cx: Float) {
            val w = bounds.width().toFloat(); val h = bounds.height().toFloat()
            if (w <= 0 || h <= 0) return
            val colors = IntArray(5) { i -> Color.argb((peak * alphas[i] * 255).toInt().coerceIn(0, 255), Color.red(tint), Color.green(tint), Color.blue(tint)) }
            // A circle of radius 0.71 * width, squashed vertically to 0.71 * height: an ellipse.
            val rx = 0.71f * w
            val shader = RadialGradient(0f, 0f, rx, colors, curve, Shader.TileMode.CLAMP)
            shader.setLocalMatrix(Matrix().apply { setScale(1f, h / w); postTranslate(cx, bounds.top.toFloat()) })
            paint.shader = shader
            canvas.drawRect(bounds, paint)
        }

        override fun draw(canvas: Canvas) {
            val p = peak(dark)
            glow(canvas, rotated(color, 22f), p * 0.85, bounds.right.toFloat())
            glow(canvas, rotated(color, -14f), p, bounds.left.toFloat())
        }

        override fun setAlpha(alpha: Int) {}
        override fun setColorFilter(colorFilter: ColorFilter?) {}
        @Deprecated("Deprecated in Java")
        override fun getOpacity() = PixelFormat.TRANSLUCENT
    }
}
