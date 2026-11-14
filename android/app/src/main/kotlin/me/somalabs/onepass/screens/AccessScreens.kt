package me.somalabs.onepass.screens

import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.os.Build
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.EditorInfo
import android.widget.CheckBox
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import me.somalabs.onepass.MainActivity
import me.somalabs.onepass.R
import me.somalabs.onepass.core.FfiPasswordRecipe
import me.somalabs.onepass.core.generatePassword
import me.somalabs.onepass.core.passwordStrengthBits
import me.somalabs.onepass.ui.Ios

/**
 * What comes before the vault, as on iPhone: the three intro cards
 * (OnboardingIntro), "Bienvenue dans OnePass / Comment veux-tu commencer ?",
 * the master password, the Secret Key to store, and the lock screen
 * ("Déverrouille OnePass").
 */
class AccessScreens(private val a: MainActivity) {
    private val ui get() = a.ui

    private fun page(content: LinearLayout.() -> Unit): View = ScrollView(a).apply {
        isFillViewport = true
        isVerticalScrollBarEnabled = false
        setBackgroundColor(ui.page)
        addView(LinearLayout(a).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(ui.dp(28), ui.dp(40), ui.dp(28), ui.dp(40))
            content()
        })
    }

    private fun appIcon(size: Int) = ui.image(R.mipmap.ic_launcher, size).apply {
        outlineProvider = object : android.view.ViewOutlineProvider() {
            override fun getOutline(view: View, outline: android.graphics.Outline) = outline.setRoundRect(0, 0, view.width, view.height, ui.dp(size * 0.225f).toFloat())
        }
        clipToOutline = true
        elevation = ui.dp(6).toFloat()
    }

    private fun LinearLayout.full(v: View, top: Int = 0) = addView(v, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = ui.dp(top) })

    fun problem(detail: String): View = page {
        addView(appIcon(88))
        addView(ui.text("OnePass", 26f, ui.label, 600).apply { setPadding(0, ui.dp(20), 0, ui.dp(8)) })
        addView(ui.text(detail, 16f, ui.secondary).apply { gravity = Gravity.CENTER })
    }

    // ---- intro ---------------------------------------------------------------------------------------

    private data class IntroCard(val icon: Int, val fr: String, val en: String, val bodyFr: String, val bodyEn: String)

    private val introCards = listOf(
        IntroCard(R.drawable.ic_key, "Tous tes mots de passe, au même endroit", "All your passwords in one place",
            "OnePass les retient pour toi et les remplit quand tu te connectes.", "OnePass remembers them for you and fills them in when you sign in."),
        IntroCard(R.drawable.ic_lock, "Toi seul as la clé", "Only you hold the key",
            "Pas de compte chez nous. Ton coffre est chiffré sur ton appareil, et même nous ne pouvons pas l'ouvrir.",
            "No account with us. Your vault is encrypted on your device, and even we can't open it."),
        IntroCard(R.drawable.ic_shield_check, "Sur tous tes appareils", "On all your devices",
            "Ton coffre reste sur cet appareil ; la synchronisation avec tes autres appareils arrive sur Android.",
            "Your vault stays on this device; syncing with your other devices is coming to Android."),
    )

    fun intro(step: Int = 0): View {
        val card = introCards[step]
        val root = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL; setBackgroundColor(ui.page) }
        val skip = LinearLayout(a).apply { gravity = Gravity.END; setPadding(ui.dp(8), ui.dp(8), ui.dp(8), 0) }
        skip.addView(a.barText(a.t("Passer", "Skip")) { a.showFull { welcome() } })
        root.addView(skip)
        val body = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL; gravity = Gravity.CENTER; setPadding(ui.dp(32), 0, ui.dp(32), 0) }
        body.addView(ui.symbolTile(card.icon, ui.accent, 96))
        body.addView(ui.text(a.t(card.fr, card.en), 28f, ui.label, 700).apply { gravity = Gravity.CENTER; setPadding(0, ui.dp(32), 0, ui.dp(12)) })
        body.addView(ui.text(a.t(card.bodyFr, card.bodyEn), 17f, ui.secondary).apply { gravity = Gravity.CENTER })
        root.addView(body, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        val dots = LinearLayout(a).apply { gravity = Gravity.CENTER; setPadding(0, 0, 0, ui.dp(20)) }
        introCards.indices.forEach { i ->
            dots.addView(View(a).apply { background = ui.rounded(if (i == step) ui.accent else ui.tertiary, 4) },
                LinearLayout.LayoutParams(ui.dp(if (i == step) 22 else 8), ui.dp(8)).apply { setMargins(ui.dp(4), 0, ui.dp(4), 0) })
        }
        root.addView(dots)
        val last = step == introCards.lastIndex
        root.addView(ui.capsule(if (last) a.t("Commencer", "Get Started") else a.t("Continuer", "Continue")) {
            a.showFull { if (last) welcome() else intro(step + 1) }
        }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { setMargins(ui.dp(28), 0, ui.dp(28), ui.dp(32)) })
        return root
    }

    // ---- welcome ----------------------------------------------------------------------------------------

    private fun welcome(): View = page {
        addView(appIcon(88))
        addView(ui.text(a.t("Bienvenue dans OnePass", "Welcome to OnePass"), 28f, ui.label, 700).apply { gravity = Gravity.CENTER; setPadding(0, ui.dp(24), 0, ui.dp(6)) })
        addView(ui.text(a.t("Comment veux-tu commencer ?", "How would you like to start?"), 17f, ui.secondary).apply { gravity = Gravity.CENTER })
        val notYet = a.t("Pas encore disponible sur Android : il faut d'abord la synchronisation entre appareils.", "Not available on Android yet: it needs device sync first.")
        full(ui.card(
            ui.row(icon = ui.symbolTile(R.drawable.ic_vault_new, ui.accent, 36), title = a.t("Créer un coffre", "Create a Vault"),
                subtitle = a.t("Première fois sur OnePass", "First time on OnePass"), minHeightDp = 68) { a.showFull { create() } },
            ui.row(icon = ui.symbolTile(R.drawable.ic_person_add, ui.blue, 36), title = a.t("Ajouter cet appareil", "Add This Device"),
                subtitle = a.t("Avec un QR code, depuis ton autre appareil", "With a QR code from your other device"), minHeightDp = 68) { a.toast(notYet) },
            ui.row(icon = ui.symbolTile(R.drawable.ic_restore, ui.orange, 36), title = a.t("Restaurer avec mon Emergency Kit", "Restore with My Emergency Kit"),
                subtitle = a.t("Aucun autre appareil sous la main", "No other device at hand"), minHeightDp = 68) { a.toast(notYet) },
        ), top = 32)
    }

    // ---- create -------------------------------------------------------------------------------------------

    private fun secretField(hint: String): Pair<LinearLayout, EditText> {
        val input = ui.field(hint, password = true)
        var shown = false
        val box = LinearLayout(a).apply {
            gravity = Gravity.CENTER_VERTICAL
            background = ui.rounded(ui.card, 14, ui.hairline)
            setPadding(0, 0, ui.dp(6), 0)
        }
        box.addView(input, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        box.addView(a.barIcon(R.drawable.ic_eye, a.t("Afficher le mot de passe", "Show Password")) { v ->
            shown = !shown
            input.inputType = InputType.TYPE_CLASS_TEXT or if (shown) InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD else InputType.TYPE_TEXT_VARIATION_PASSWORD
            input.typeface = Typeface.DEFAULT
            input.setSelection(input.text.length)
            ((v as FrameLayout).getChildAt(0) as android.widget.ImageView).setImageResource(if (shown) R.drawable.ic_eye_off else R.drawable.ic_eye)
        })
        return box to input
    }

    private fun create(): View = page {
        gravity = Gravity.START
        addView(ui.text(a.t("Ton mot de passe maître", "Your master password"), 28f, ui.label, 700))
        addView(ui.text(a.t("Il ouvre ton coffre. Personne ne peut le retrouver pour toi : ni nous, ni personne.",
            "It opens your vault. Nobody can recover it for you: not us, not anyone."), 16f, ui.secondary).apply { setPadding(0, ui.dp(8), 0, 0) })
        val name = ui.field(a.t("Ton prénom (facultatif)", "Your first name (optional)")).apply {
            background = ui.rounded(ui.card, 14, ui.hairline)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_WORDS
        }
        full(name, 24)
        val (box1, pw) = secretField(a.t("Mot de passe maître", "Master Password"))
        val (box2, pw2) = secretField(a.t("Confirme ton mot de passe", "Confirm your password"))
        full(box1, 12)
        val meter = LinearLayout(a).apply { gravity = Gravity.CENTER_VERTICAL; setPadding(ui.dp(4), ui.dp(8), ui.dp(4), 0) }
        full(meter)
        full(box2, 12)
        val err = ui.text("", 14f, ui.red).apply { setPadding(ui.dp(4), ui.dp(8), ui.dp(4), 0) }
        full(err)
        full(ui.text(a.t("Conseil : cinq mots tirés au hasard (« tapis-orage-girafe-violon-nuage ») sont plus solides et plus faciles à retenir qu'un mot compliqué. « Générer » en tire cinq pour toi.",
            "Tip: five random words (“carpet-storm-giraffe-violin-cloud”) are stronger and easier to remember than one complicated word. “Generate” picks five for you."), 13f, ui.secondary), 12)
        fun drawMeter() {
            meter.removeAllViews()
            val p = pw.text.toString()
            if (p.isEmpty()) return
            val bits = passwordStrengthBits(p)
            val level = listOf(40.0, 60.0, 80.0, 100.0).count { bits >= it }
            val color = when (level) { 0, 1 -> ui.red; 2 -> ui.orange; else -> ui.green }
            for (i in 0 until 4) meter.addView(View(a).apply { background = ui.rounded(if (i < level) color else ui.fill, 2) }, LinearLayout.LayoutParams(0, ui.dp(4), 1f).apply { marginEnd = ui.dp(4) })
            meter.addView(ui.text(if (level >= 3) a.t("Assez solide pour ton coffre", "Strong enough for your vault") else a.t("Trop faible", "Too Weak"), 12f, ui.secondary).apply { setPadding(ui.dp(6), 0, 0, 0) })
        }
        pw.addTextChangedListener(object : android.text.TextWatcher {
            override fun afterTextChanged(e: android.text.Editable?) = drawMeter()
            override fun beforeTextChanged(s: CharSequence?, x: Int, y: Int, z: Int) {}
            override fun onTextChanged(s: CharSequence?, x: Int, y: Int, z: Int) {}
        })
        val buttons = LinearLayout(a)
        buttons.addView(ui.capsule(a.t("Générer", "Generate"), prominent = false) {
            val p = generatePassword(FfiPasswordRecipe.Words(5u, "-", a.t("fr", "en") == "fr", false))
            pw.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
            pw2.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
            pw.typeface = Typeface.DEFAULT; pw2.typeface = Typeface.DEFAULT
            pw.setText(p); pw2.setText(p)
        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { marginEnd = ui.dp(6) })
        lateinit var go: TextView
        go = ui.capsule(a.t("Créer un coffre", "Create a Vault")) {
            val p1 = pw.text.toString()
            when {
                p1 != pw2.text.toString() -> err.text = a.t("Les deux saisies doivent être identiques.", "Both entries must match.")
                p1.length < 10 || passwordStrengthBits(p1) < 60 -> err.text = a.t("Pas encore assez solide : ajoute un mot, ou touche Générer.", "Not strong enough yet. Add a word, or tap Generate.")
                else -> {
                    go.isEnabled = false
                    go.text = a.t("Création du coffre...", "Creating Vault...")
                    err.text = ""
                    val chars = p1.toCharArray()
                    val first = name.text.toString().trim()
                    pw.text.clear(); pw2.text.clear()
                    a.background({
                        val key = a.vault.create(chars, Build.MODEL ?: "Android")
                        if (first.isNotEmpty()) runCatching { a.vault.session?.setProfile(first, ByteArray(0)) }
                        key
                    }) { r ->
                        chars.fill(' ')
                        r.onSuccess { key -> a.showFull { secretKey(key) } }.onFailure {
                            err.text = a.message(it)
                            go.isEnabled = true
                            go.text = a.t("Créer un coffre", "Create a Vault")
                        }
                    }
                }
            }
        }
        buttons.addView(go, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { marginStart = ui.dp(6) })
        full(buttons, 24)
        full(a.link(a.t("Retour", "Back")) { a.showFull { welcome() } }.apply { gravity = Gravity.CENTER }, 8)
    }

    /** The Secret Key, shown once: to store with the master password (Emergency Kit). */
    private fun secretKey(key: String): View = page {
        gravity = Gravity.START
        addView(ui.text(a.t("Ton Emergency Kit", "Your Emergency Kit"), 28f, ui.label, 700))
        addView(ui.text(a.t("Ce kit plus ton mot de passe maître donnent un accès complet à ton coffre. Recopie la Secret Key sur papier et range la feuille hors ligne ; ne la photographie pas.",
            "This kit plus your master password give full access to your vault. Copy the Secret Key on paper and keep the sheet offline; don't photograph it."), 16f, ui.secondary).apply { setPadding(0, ui.dp(8), 0, 0) })
        val box = LinearLayout(a).apply {
            orientation = LinearLayout.VERTICAL
            background = ui.rounded(ui.card, Ios.Radius.CARD, ui.accent)
            setPadding(ui.dp(16), ui.dp(14), ui.dp(16), ui.dp(16))
        }
        box.addView(ui.text("SECRET KEY", 13f, ui.readableAccent, 600).apply { letterSpacing = 0.06f })
        box.addView(ui.text(key, 19f, ui.label, 500).apply { typeface = Typeface.MONOSPACE; setPadding(0, ui.dp(8), 0, 0) })
        full(box, 24)
        val noted = CheckBox(a).apply {
            text = a.t("Coche la case une fois ta Secret Key rangée.", "Check the box once your Secret Key is stored safely.")
            setTextColor(ui.label)
            buttonTintList = ColorStateList.valueOf(ui.accent)
        }
        full(noted, 16)
        val next = ui.capsule(a.t("Continuer", "Continue")) { a.openTabs() }.apply { isEnabled = false; alpha = 0.45f }
        noted.setOnCheckedChangeListener { _, on -> next.isEnabled = on; next.alpha = if (on) 1f else 0.45f }
        full(next, 16)
    }

    private fun showKeyboard(e: EditText) {
        e.requestFocus()
        a.getSystemService(android.view.inputmethod.InputMethodManager::class.java).showSoftInput(e, 0)
    }

    // ---- lock ------------------------------------------------------------------------------------------------

    fun lock(): View {
        val (box, pw) = secretField(a.t("Mot de passe maître", "Master Password"))
        val err = ui.text("", 15f, ui.red).apply { gravity = Gravity.CENTER; setPadding(0, ui.dp(12), 0, 0) }
        val busy = ui.text("", 15f, ui.secondary).apply { gravity = Gravity.CENTER; setPadding(0, ui.dp(12), 0, 0) }
        lateinit var go: View
        val submit = submit@{
            if (pw.text.isEmpty()) return@submit
            go.isEnabled = false
            busy.text = a.t("Déverrouillage...", "Unlocking...")
            err.text = ""
            val chars = pw.text.toString().toCharArray()
            a.background({ a.vault.unlock(chars) }) { r ->
                chars.fill(' ')
                busy.text = ""
                r.onSuccess {
                    pw.text.clear()
                    pw.announceForAccessibility(a.t("OnePass déverrouillé", "OnePass unlocked"))
                    a.openTabs()
                }.onFailure {
                    err.text = if (it is me.somalabs.onepass.core.OnePassException.WrongPassword) a.t("Mot de passe incorrect.", "Incorrect password.") + " " + a.t("Tu peux réessayer.", "You can try again.") else a.message(it)
                    box.background = ui.rounded(ui.card, 14, ui.red)
                    pw.selectAll()
                    go.isEnabled = true
                }
            }
        }
        go = FrameLayout(a).apply {
            background = ui.pressable(android.graphics.drawable.GradientDrawable().apply { shape = android.graphics.drawable.GradientDrawable.OVAL; setColor(ui.accent) }, 18)
            contentDescription = a.t("Déverrouiller", "Unlock")
            isClickable = true
            setOnClickListener { submit() }
            addView(ui.glyph(R.drawable.ic_arrow_forward, Color.WHITE, 20), FrameLayout.LayoutParams(ui.dp(20), ui.dp(20), Gravity.CENTER))
        }
        box.addView(go, LinearLayout.LayoutParams(ui.dp(36), ui.dp(36)).apply { marginEnd = ui.dp(4) })
        pw.imeOptions = EditorInfo.IME_ACTION_GO or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
        pw.setOnEditorActionListener { _, _, _ -> submit(); true }

        // Fingerprint or face first, when it is on: the system sheet comes up by itself once,
        // the button beside the field asks again.
        val bio = a.vault.biometrics
        var bioButton: View? = null
        val canBio = bio.enrolled && bio.availability() == me.somalabs.onepass.vault.BiometricUnlock.Availability.AVAILABLE
        var bioRunning = false
        fun biometric() {
            if (bioRunning) return
            bioRunning = true
            err.text = ""
            bio.unlock(a, a.t("Déverrouille OnePass", "Unlock OnePass"), a.profileName.ifEmpty { a.t("Compte OnePass", "OnePass Account") },
                a.t("Utiliser le mot de passe maître", "Use the master password")) { outcome ->
                bioRunning = false
                when (outcome) {
                    is me.somalabs.onepass.vault.BiometricUnlock.Outcome.Unlocked -> {
                        busy.text = a.t("Déverrouillage...", "Unlocking...")
                        val auk = outcome.auk
                        a.background({ a.vault.unlockWithAuk(auk) }) { r ->
                            busy.text = ""
                            r.onSuccess {
                                pw.announceForAccessibility(a.t("OnePass déverrouillé", "OnePass unlocked"))
                                a.openTabs()
                            }.onFailure { err.text = a.message(it) }
                        }
                    }
                    is me.somalabs.onepass.vault.BiometricUnlock.Outcome.Cancelled -> showKeyboard(pw)
                    is me.somalabs.onepass.vault.BiometricUnlock.Outcome.PasswordRequired -> {
                        err.text = when (outcome.message) {
                            me.somalabs.onepass.vault.BiometricUnlock.Reason.REBOOTED -> a.t("Le mot de passe maître est demandé après un redémarrage.", "Your master password is required after a restart.")
                            me.somalabs.onepass.vault.BiometricUnlock.Reason.EXPIRED -> a.t("Le mot de passe maître est demandé régulièrement.", "Your master password is required from time to time.")
                            me.somalabs.onepass.vault.BiometricUnlock.Reason.INVALIDATED -> a.t("La biométrie a changé : saisis ton mot de passe maître.", "Biometrics changed. Enter your master password.")
                            me.somalabs.onepass.vault.BiometricUnlock.Reason.LOCKED_OUT -> a.t("La biométrie est temporairement bloquée : saisis ton mot de passe maître.", "Biometrics are temporarily locked. Enter your master password.")
                            else -> ""
                        }
                        if (!bio.enrolled) bioButton?.visibility = View.GONE
                        showKeyboard(pw)
                    }
                }
            }
        }
        if (canBio) {
            bioButton = a.barIcon(R.drawable.ic_fingerprint, a.t("Déverrouiller avec la biométrie", "Unlock with Biometrics")) { biometric() }
            box.addView(bioButton, box.childCount - 2)
            pw.addTextChangedListener(object : android.text.TextWatcher {
                override fun afterTextChanged(e: android.text.Editable?) { bioButton?.visibility = if (e.isNullOrEmpty() && bio.enrolled) View.VISIBLE else View.GONE }
                override fun beforeTextChanged(s: CharSequence?, x: Int, y: Int, z: Int) {}
                override fun onTextChanged(s: CharSequence?, x: Int, y: Int, z: Int) {}
            })
        }
        val v = page {
            gravity = Gravity.CENTER
            addView(View(a), LinearLayout.LayoutParams(1, ui.dp(60)))
            addView(appIcon(96))
            addView(ui.text(a.t("Déverrouille OnePass", "Unlock OnePass"), 26f, ui.label, 600).apply { gravity = Gravity.CENTER; setPadding(0, ui.dp(20), 0, 0) })
            val name = runCatching { a.profileName }.getOrDefault("")
            val capsule = LinearLayout(a).apply {
                gravity = Gravity.CENTER_VERTICAL
                background = ui.rounded(ui.fill, 16)
                setPadding(ui.dp(3), ui.dp(3), ui.dp(12), ui.dp(3))
            }
            capsule.addView(ui.monogram(name.take(1).uppercase().ifEmpty { "1" }, ui.accent, 26))
            capsule.addView(ui.text(name.ifEmpty { a.t("Compte OnePass", "OnePass Account") }, 15f, ui.secondary, 500).apply { setPadding(ui.dp(8), 0, 0, 0) })
            addView(capsule, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = ui.dp(10) })
            full(box, 26)
            full(err)
            full(busy)
            val protection = ui.text("", 13f, ui.tertiary).apply { gravity = Gravity.CENTER; setPadding(0, ui.dp(24), 0, 0) }
            full(protection)
            a.background({ a.vault.protection }) { r -> protection.text = a.t("Clés de l'appareil protégées par ", "Device keys protected by ") + r.getOrDefault("Android Keystore") }
            if (canBio) bio.passwordDueAt()?.let { due ->
                val days = maxOf(1L, Math.ceil((due - System.currentTimeMillis()) / 86_400_000.0).toLong())
                full(ui.text(if (days == 1L) a.t("Mot de passe maître redemandé dans 1 jour, puis tous les 14 jours.", "Master password required again in 1 day, then every 14 days.")
                    else a.t("Mot de passe maître redemandé dans $days jours, puis tous les 14 jours.", "Master password required again in $days days, then every 14 days."), 13f, ui.tertiary).apply { gravity = Gravity.CENTER; setPadding(0, ui.dp(8), 0, 0) })
            }
        }
        if (canBio) v.postDelayed({ if (v.isAttachedToWindow) biometric() }, 350) else pw.requestFocus()
        return v
    }
}
