package me.somalabs.onepass.fill

import android.app.Activity
import android.graphics.Color
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.EditorInfo
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import java.util.concurrent.Executors
import me.somalabs.onepass.R
import me.somalabs.onepass.core.OnePassException
import me.somalabs.onepass.ui.Ios
import me.somalabs.onepass.vault.BiometricUnlock
import me.somalabs.onepass.vault.DeviceVault

/**
 * "Déverrouille OnePass" for the AutoFill and passkey screens (iPhone: the
 * extension's unlock view): fingerprint or face first when it is on, else the
 * master password. The session is the app's own (one vault per process).
 */
class Unlocker(private val activity: Activity, private val ui: Ios, private val reason: String?) {
    private val worker = Executors.newSingleThreadExecutor()
    private val vault = DeviceVault.get(activity)

    fun t(fr: String, en: String) = if (activity.resources.configuration.locales[0].language == "fr") fr else en

    fun view(onUnlocked: () -> Unit, onCancel: () -> Unit): View {
        val col = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(ui.dp(28), ui.dp(72), ui.dp(28), ui.dp(40))
        }
        val bar = LinearLayout(activity).apply { gravity = Gravity.START }
        bar.addView(ui.text(t("Annuler", "Cancel"), 17f, ui.accent).apply {
            setPadding(ui.dp(4), ui.dp(4), ui.dp(4), ui.dp(4)); isClickable = true; setOnClickListener { onCancel() }
        })
        col.addView(bar, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        col.addView(ui.image(R.mipmap.ic_launcher, 80).apply {
            outlineProvider = object : android.view.ViewOutlineProvider() {
                override fun getOutline(view: View, outline: android.graphics.Outline) = outline.setRoundRect(0, 0, view.width, view.height, ui.dp(18).toFloat())
            }
            clipToOutline = true
            (layoutParams as LinearLayout.LayoutParams).topMargin = ui.dp(24)
        })
        col.addView(ui.text(t("Déverrouille OnePass", "Unlock OnePass"), 24f, ui.label, 600).apply { gravity = Gravity.CENTER; setPadding(0, ui.dp(18), 0, ui.dp(4)) })
        reason?.let { col.addView(ui.text(it, 15f, ui.secondary).apply { gravity = Gravity.CENTER }) }
        val pw = ui.field(t("Mot de passe maître", "Master Password"), password = true).apply {
            imeOptions = EditorInfo.IME_ACTION_GO or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            typeface = android.graphics.Typeface.DEFAULT
        }
        val box = LinearLayout(activity).apply {
            gravity = Gravity.CENTER_VERTICAL
            background = ui.rounded(ui.card, 14, ui.hairline)
            setPadding(0, 0, ui.dp(6), 0)
        }
        box.addView(pw, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        val err = ui.text("", 15f, ui.red).apply { gravity = Gravity.CENTER; setPadding(0, ui.dp(12), 0, 0) }
        var busy = false
        fun submit() {
            if (busy || pw.text.isEmpty()) return
            busy = true
            err.text = ""
            val chars = pw.text.toString().toCharArray()
            pw.text.clear()
            worker.execute {
                val r = runCatching { vault.unlock(chars) }
                chars.fill(' ')
                activity.runOnUiThread {
                    busy = false
                    r.onSuccess { onUnlocked() }.onFailure {
                        err.text = if (it is OnePassException.WrongPassword) t("Mot de passe incorrect.", "Incorrect password.") + " " + t("Tu peux réessayer.", "You can try again.")
                        else t("Erreur : ", "Error: ") + it.javaClass.simpleName
                    }
                }
            }
        }
        pw.setOnEditorActionListener { _, _, _ -> submit(); true }
        val go = FrameLayout(activity).apply {
            background = android.graphics.drawable.GradientDrawable().apply { shape = android.graphics.drawable.GradientDrawable.OVAL; setColor(ui.accent) }
            contentDescription = t("Déverrouiller", "Unlock")
            isClickable = true
            setOnClickListener { submit() }
            addView(ui.glyph(R.drawable.ic_arrow_forward, Color.WHITE, 20), FrameLayout.LayoutParams(ui.dp(20), ui.dp(20), Gravity.CENTER))
        }
        val bio = vault.biometrics
        val canBio = bio.enrolled && bio.availability() == BiometricUnlock.Availability.AVAILABLE
        fun biometric() {
            bio.unlock(activity, t("Déverrouille OnePass", "Unlock OnePass"), reason ?: "OnePass", t("Utiliser le mot de passe maître", "Use the master password")) { o ->
                when (o) {
                    is BiometricUnlock.Outcome.Unlocked -> worker.execute {
                        val r = runCatching { vault.unlockWithAuk(o.auk) }
                        activity.runOnUiThread { r.onSuccess { onUnlocked() }.onFailure { err.text = it.javaClass.simpleName } }
                    }
                    else -> { pw.requestFocus() }
                }
            }
        }
        if (canBio) box.addView(FrameLayout(activity).apply {
            contentDescription = t("Déverrouiller avec la biométrie", "Unlock with Biometrics")
            isClickable = true
            setPadding(ui.dp(8), ui.dp(10), ui.dp(8), ui.dp(10))
            addView(ui.glyph(R.drawable.ic_fingerprint, ui.accent, 24))
            setOnClickListener { biometric() }
        })
        box.addView(go, LinearLayout.LayoutParams(ui.dp(36), ui.dp(36)).apply { marginEnd = ui.dp(4) })
        col.addView(box, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = ui.dp(26) })
        col.addView(err)
        val root = ScrollView(activity).apply { setBackgroundColor(ui.page); isFillViewport = true; addView(col) }
        if (canBio) root.postDelayed({ if (root.isAttachedToWindow) biometric() }, 300) else pw.requestFocus()
        return root
    }

    fun close() = worker.shutdown()
}
