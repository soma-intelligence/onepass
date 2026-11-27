package me.somalabs.onepass.fill

import android.app.Activity
import android.app.assist.AssistStructure
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.service.autofill.Dataset
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.LinearLayout
import android.widget.ScrollView
import java.util.concurrent.Executors
import me.somalabs.onepass.R
import me.somalabs.onepass.autofill.FormParser
import me.somalabs.onepass.autofill.ParsedForm
import me.somalabs.onepass.core.FfiAutofillCandidate
import me.somalabs.onepass.core.FfiAutofillService
import me.somalabs.onepass.core.FfiFieldType
import me.somalabs.onepass.core.FfiFieldValue
import me.somalabs.onepass.core.FfiItem
import me.somalabs.onepass.core.FfiItemType
import me.somalabs.onepass.core.FfiMatchQuality
import me.somalabs.onepass.core.FfiMatchRule
import me.somalabs.onepass.core.FfiUrl
import me.somalabs.onepass.core.Session
import me.somalabs.onepass.core.totpNow
import me.somalabs.onepass.ui.Ios
import me.somalabs.onepass.vault.DeviceVault
import me.somalabs.onepass.vaultkit.core.CoreLoader

/**
 * The AutoFill screens (iPhone: the extension's views), started by the system
 * from a Cleon suggestion or a save prompt:
 * - [ACTION_UNLOCK]: the vault was locked; unlock, then answer with the Logins.
 * - [ACTION_PICK]: the user picked one Login; return its values (unlocking first if needed).
 * - [ACTION_SEARCH]: "Rechercher dans Cleon", every Login, with a search.
 * - [ACTION_SAVE]: "Enregistrer dans Cleon", a new Login or an update.
 *
 * Not exported; the Intents carry ids only.
 */
class FillActivity : Activity() {
    private lateinit var ui: Ios
    private val worker = Executors.newSingleThreadExecutor()
    private val vault by lazy { DeviceVault.get(this) }
    private var unlocker: Unlocker? = null
    private var form: ParsedForm? = null
    private var service: FfiAutofillService? = null

    private fun t(fr: String, en: String) = if (resources.configuration.locales[0].language == "fr") fr else en
    private val debuggable get() = applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!debuggable) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        CoreLoader.ensureLoaded()
        ui = Ios(this)
        @Suppress("DEPRECATION")
        val structure: AssistStructure? = if (Build.VERSION.SDK_INT >= 33) intent.getParcelableExtra(AutofillManager.EXTRA_ASSIST_STRUCTURE, AssistStructure::class.java)
        else intent.getParcelableExtra(AutofillManager.EXTRA_ASSIST_STRUCTURE)
        form = structure?.let { runCatching { FormParser.parse(it) }.getOrNull() }
        service = form?.let { Fills.serviceOf(it) }
        if (intent.action != ACTION_SAVE && (form == null || service == null)) return cancel()
        vault.lockIfIdle()
        if (vault.session == null) {
            if (vault.state() != DeviceVault.State.LOCKED) return cancel()
            window.setBackgroundDrawable(android.graphics.drawable.ColorDrawable(ui.page))
            val u = Unlocker(this, ui, form?.let { t("pour remplir ", "to fill ") + Fills.label(this, it) })
            unlocker = u
            setContentView(u.view({ proceed() }, { cancel() }))
        } else proceed()
    }

    override fun onDestroy() {
        unlocker?.close()
        worker.shutdown()
        super.onDestroy()
    }

    private fun cancel() {
        setResult(RESULT_CANCELED)
        finish()
    }

    private fun proceed() {
        val s = vault.session ?: return cancel()
        when (intent.action) {
            ACTION_UNLOCK -> {
                val f = form ?: return cancel()
                val response = runCatching { Fills.response(this, f, service!!, s) }.getOrNull() ?: return cancel()
                setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, response))
                finish()
            }
            ACTION_PICK -> fill(s, intent.getStringExtra(EXTRA_VAULT) ?: return cancel(), intent.getStringExtra(EXTRA_ITEM) ?: return cancel())
            ACTION_SEARCH -> search(s)
            ACTION_SAVE -> save(s)
            else -> cancel()
        }
    }

    // ---- fill ----------------------------------------------------------------------------------

    private fun username(item: FfiItem): String? {
        val fields = item.sections.flatMap { it.fields }
        val f = fields.firstOrNull { it.id == "username" } ?: fields.firstOrNull { it.kind == FfiFieldType.EMAIL }
        return f?.value?.let { textOf(it) }
    }

    private fun textOf(v: FfiFieldValue): String? = when (v) {
        is FfiFieldValue.Text -> v.value
        is FfiFieldValue.Email -> v.value
        is FfiFieldValue.Password -> v.value
        is FfiFieldValue.Concealed -> v.value
        is FfiFieldValue.Otp -> v.value
        is FfiFieldValue.Phone -> v.value
        else -> null
    }

    /** Returns the picked Login's values to the system, and remembers the choice for this site or app. */
    private fun fill(s: Session, vaultId: String, itemId: String) {
        val f = form ?: return cancel()
        val svc = service ?: return cancel()
        val item = runCatching { s.item(vaultId, itemId) }.getOrNull() ?: return cancel()
        val fields = item.sections.flatMap { it.fields }
        val password = fields.firstOrNull { it.kind == FfiFieldType.PASSWORD }?.value?.let { textOf(it) }
        val otp = fields.firstOrNull { it.kind == FfiFieldType.OTP }?.value?.let { textOf(it) }
            ?.let { runCatching { totpNow(it, (System.currentTimeMillis() / 1000).toULong()).code }.getOrNull() }
        val user = username(item)
        val b = Dataset.Builder(Fills.presentation(this, item.title, user))
        var any = false
        @Suppress("DEPRECATION")
        fun set(ids: List<android.view.autofill.AutofillId>, v: String?) {
            if (v.isNullOrEmpty()) return
            ids.forEach { b.setValue(it, AutofillValue.forText(v)); any = true }
        }
        set(f.usernames, user)
        set(f.passwords, password)
        set(f.otps, otp)
        if (!any) return cancel()
        val dataset = b.build()
        val record = "$vaultId:$itemId"
        worker.execute { runCatching { s.noteAutofillServiceUse(record, svc, emptyList()) } }
        setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset))
        finish()
    }

    // ---- search --------------------------------------------------------------------------------

    private fun page(title: String, content: LinearLayout.() -> Unit) {
        window.setBackgroundDrawable(android.graphics.drawable.ColorDrawable(ui.page))
        val col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(0, ui.dp(40), 0, ui.dp(40)) }
        val bar = LinearLayout(this).apply { gravity = Gravity.CENTER_VERTICAL; setPadding(ui.dp(12), ui.dp(8), ui.dp(12), ui.dp(4)) }
        bar.addView(ui.text(t("Annuler", "Cancel"), 17f, ui.accent).apply { setPadding(ui.dp(8), ui.dp(8), ui.dp(8), ui.dp(8)); isClickable = true; setOnClickListener { cancel() } })
        bar.addView(ui.text(title, 17f, ui.label, 600).apply { gravity = Gravity.CENTER }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        bar.addView(View(this), LinearLayout.LayoutParams(ui.dp(80), 1))
        col.addView(bar)
        col.content()
        setContentView(ScrollView(this).apply { isFillViewport = true; setBackgroundColor(ui.page); addView(col) })
    }

    private fun search(s: Session) {
        val f = form ?: return cancel()
        val svc = service ?: return cancel()
        val all = runCatching { s.autofillServiceCandidates(svc, true, emptyList()) }.getOrDefault(emptyList())
        val label = Fills.label(this, f)
        page(t("Choisis un compte", "Choose an Account")) {
            val search = ui.searchField(t("Rechercher dans Cleon", "Search Cleon"))
            addView(ui.inset(search, top = Ios.Space.S))
            addView(ui.footnote(t("pour ", "For ") + label))
            val list = LinearLayout(this@FillActivity).apply { orientation = LinearLayout.VERTICAL }
            addView(list)
            fun draw(q: String) {
                list.removeAllViews()
                val shown = all.filter { q.isBlank() || it.title.contains(q, true) || it.user.contains(q, true) || (it.url?.contains(q, true) == true) }
                if (shown.isEmpty()) { list.addView(ui.footnote(t("Aucun résultat.", "No results.")).apply { gravity = Gravity.CENTER }); return }
                val (here, other) = shown.partition { it.quality != FfiMatchQuality.OTHER }
                fun section(title: String?, items: List<FfiAutofillCandidate>) {
                    if (items.isEmpty()) return
                    title?.let { list.addView(ui.capsLabel(it)) }
                    list.addView(ui.inset(ui.card(*items.take(200).map { c ->
                        ui.row(icon = ui.image(R.mipmap.ic_launcher, 30), title = c.title.ifBlank { c.user }, subtitle = c.user.takeIf { it != c.title } ?: c.url) { picked(s, c) }
                    }.toTypedArray()), top = Ios.Space.S))
                }
                section(if (here.isNotEmpty()) t("pour ce site", "For this site") else null, here)
                section(if (here.isNotEmpty()) t("autres éléments", "Other items") else null, other)
            }
            (search.getChildAt(1) as android.widget.EditText).addTextChangedListener(object : android.text.TextWatcher {
                override fun afterTextChanged(e: android.text.Editable?) = draw(e?.toString().orEmpty())
                override fun beforeTextChanged(x: CharSequence?, a: Int, b: Int, c: Int) {}
                override fun onTextChanged(x: CharSequence?, a: Int, b: Int, c: Int) {}
            })
            draw("")
        }
    }

    /** A Login picked by hand. For an app it did not match, offer to remember the app on it. */
    private fun picked(s: Session, c: FfiAutofillCandidate) {
        val svc = service
        if (svc is FfiAutofillService.App && c.quality == FfiMatchQuality.OTHER) {
            val app = form?.let { Fills.label(this, it) } ?: svc.id
            page(t("Toujours utiliser ce login pour $app ?", "Always Use This Login for $app?")) {
                addView(ui.footnote(t("Identifiant de l'app : ${svc.id}\nOnePass proposera ce login en premier dans cette app la prochaine fois.",
                    "App ID: ${svc.id}\nOnePass will suggest this login first in this app next time.")))
                addView(ui.inset(ui.card(
                    ui.row(title = t("Toujours utiliser pour cette app", "Always Use for This App"), titleColor = ui.readableAccent, chevron = false) {
                        worker.execute {
                            runCatching { s.item(c.vaultId, c.itemId).let { it.apps = (it.apps + svc.id).distinct(); s.saveItem(it) } }
                            runOnUiThread { fill(s, c.vaultId, c.itemId) }
                        }
                    },
                    ui.row(title = t("Seulement cette fois", "Just This Once"), chevron = false) { fill(s, c.vaultId, c.itemId) },
                ), top = Ios.Space.L))
            }
        } else fill(s, c.vaultId, c.itemId)
    }

    // ---- save ----------------------------------------------------------------------------------

    private fun save(s: Session) {
        val pending = PendingSaves.take(intent.getStringExtra(EXTRA_TOKEN)) ?: return cancel()
        val sameUser = runCatching { s.autofillServiceCandidates(pending.service, false, emptyList()) }.getOrDefault(emptyList())
            .filter { it.quality != FfiMatchQuality.OTHER && it.user.equals(pending.username, ignoreCase = true) }
        val vaults = runCatching { s.vaults() }.getOrDefault(emptyList())
        page(t("Enregistrer dans Cleon", "Save in Cleon")) {
            addView(ui.inset(ui.card(
                ui.row(icon = ui.image(R.mipmap.ic_launcher, 30), title = pending.title, subtitle = pending.username.ifBlank { null }, chevron = false),
                ui.row(title = t("mot de passe", "Password"), value = "••••••••••", chevron = false),
            ), top = Ios.Space.S))
            val rows = mutableListOf<View>()
            sameUser.forEach { c ->
                rows += ui.row(title = t("Mettre à jour l'élément existant", "Update Existing Item"), subtitle = c.title, titleColor = ui.readableAccent, chevron = false) {
                    store(s) {
                        val item = s.item(c.vaultId, c.itemId)
                        item.sections = item.sections.map { sec -> sec.copy(fields = sec.fields.map { f -> if (f.kind == FfiFieldType.PASSWORD && f.id == "password") f.copy(value = FfiFieldValue.Password(pending.password)) else f }) }
                        s.saveItem(item)
                    }
                }
            }
            if (vaults.isNotEmpty()) rows += ui.row(title = if (sameUser.isEmpty()) t("Enregistrer", "Save") else t("Enregistrer comme nouvel élément", "Save as New Item"), titleColor = ui.readableAccent, chevron = false) {
                store(s) {
                    val n = s.newItem(vaults.first().id, FfiItemType.LOGIN, pending.title)
                    n.sections = n.sections.map { sec ->
                        sec.copy(fields = sec.fields.map { f ->
                            when {
                                f.id == "username" && pending.username.isNotEmpty() -> f.copy(value = if (f.kind == FfiFieldType.EMAIL) FfiFieldValue.Email(pending.username) else FfiFieldValue.Text(pending.username))
                                f.id == "password" -> f.copy(value = FfiFieldValue.Password(pending.password))
                                else -> f
                            }
                        })
                    }
                    when (val svc = pending.service) {
                        is FfiAutofillService.Site -> n.urls = listOf(FfiUrl("", "https://" + svc.value, FfiMatchRule.DOMAIN, true))
                        is FfiAutofillService.App -> n.apps = listOf(svc.id)
                    }
                    s.saveItem(n)
                }
            }
            addView(ui.inset(ui.card(*rows.toTypedArray()), top = Ios.Space.L))
            if (sameUser.isNotEmpty()) addView(ui.footnote(t("Le nouveau mot de passe remplace l'ancien, qui reste dans l'historique de l'élément.", "The new password replaces the old one, which stays in the item's history.")))
        }
    }

    private fun store(@Suppress("UNUSED_PARAMETER") s: Session, work: () -> Unit) {
        worker.execute {
            val r = runCatching(work)
            runOnUiThread {
                r.onSuccess {
                    android.widget.Toast.makeText(this, t("Enregistré dans Cleon", "Saved in Cleon"), android.widget.Toast.LENGTH_SHORT).show()
                    setResult(RESULT_OK)
                    finish()
                }.onFailure { android.widget.Toast.makeText(this, t("Erreur : ", "Error: ") + it.javaClass.simpleName, android.widget.Toast.LENGTH_LONG).show() }
            }
        }
    }

    companion object {
        const val ACTION_UNLOCK = "me.somalabs.onepass.fill.UNLOCK"
        const val ACTION_PICK = "me.somalabs.onepass.fill.PICK"
        const val ACTION_SEARCH = "me.somalabs.onepass.fill.SEARCH"
        const val ACTION_SAVE = "me.somalabs.onepass.fill.SAVE"
        const val EXTRA_VAULT = "vault"
        const val EXTRA_ITEM = "item"
        const val EXTRA_TOKEN = "token"
    }
}
