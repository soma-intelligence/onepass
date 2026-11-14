package me.somalabs.onepass.fill

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.widget.RemoteViews
import java.security.SecureRandom
import me.somalabs.onepass.R
import me.somalabs.onepass.autofill.FormParser
import me.somalabs.onepass.autofill.ParsedForm
import me.somalabs.onepass.core.FfiAutofillCandidate
import me.somalabs.onepass.core.FfiAutofillRequest
import me.somalabs.onepass.core.FfiAutofillService
import me.somalabs.onepass.core.Session
import me.somalabs.onepass.vault.DeviceVault
import me.somalabs.onepass.vaultkit.core.CoreLoader

/**
 * Android AutoFill (iPhone: the AutoFill extension). For a login form in an
 * app or a browser it offers the matching Logins (core plan, then
 * candidates), "Rechercher dans OnePass" for any other, and a save prompt
 * for a new login.
 *
 * No secret ever goes to the system before the user picks a Login: each
 * suggestion is an authenticated dataset, and [FillActivity] (ours, not
 * exported) unlocks if needed and returns the values of that one Login. A
 * locked vault gives one "Déverrouille OnePass" entry. A save request leaves
 * the typed values in this process only ([PendingSaves]), never in an Intent.
 */
class OnePassAutofillService : AutofillService() {
    override fun onFillRequest(request: FillRequest, cancellationSignal: CancellationSignal, callback: FillCallback) {
        val response = runCatching {
            CoreLoader.ensureLoaded()
            val structure = request.fillContexts.last().structure
            val form = FormParser.parse(structure)
            if (own(structure) || !form.fillable) return@runCatching null
            val service = Fills.serviceOf(form) ?: return@runCatching null
            val vault = DeviceVault.get(this)
            vault.lockIfIdle()
            when (vault.state()) {
                DeviceVault.State.UNLOCKED -> Fills.response(this, form, service, vault.session ?: return@runCatching null)
                DeviceVault.State.LOCKED -> Fills.lockedResponse(this, form)
                else -> null
            }
        }.getOrNull()
        callback.onSuccess(response)
    }

    /** OnePass's own screens are never filled (the debug login demo aside, for emulator tests). */
    private fun own(st: android.app.assist.AssistStructure): Boolean {
        val c = st.activityComponent ?: return false
        return c.packageName == packageName && !c.className.endsWith(".LoginDemoActivity")
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        val form = runCatching { FormParser.parse(request.fillContexts.last().structure) }.getOrNull()
        val password = form?.passwordValue
        if (form == null || password.isNullOrEmpty() || own(request.fillContexts.last().structure)) return callback.onSuccess()
        val service = Fills.serviceOf(form) ?: return callback.onSuccess()
        val token = PendingSaves.put(PendingSaves.Save(service, Fills.label(this, form), form.usernameValue.orEmpty(), password))
        val intent = Intent(this, FillActivity::class.java).setAction(FillActivity.ACTION_SAVE).putExtra(FillActivity.EXTRA_TOKEN, token)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val pi = PendingIntent.getActivity(this, token.hashCode(), intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_CANCEL_CURRENT)
        callback.onSuccess(pi.intentSender)
    }
}

/** A save waiting for the user, kept in memory for 10 minutes; the Intent carries only its token. */
object PendingSaves {
    class Save(val service: FfiAutofillService, val title: String, val username: String, val password: String) {
        val at = System.currentTimeMillis()
    }

    private val saves = mutableMapOf<String, Save>()

    @Synchronized
    fun put(s: Save): String {
        saves.entries.removeAll { System.currentTimeMillis() - it.value.at > 600_000 }
        val token = ByteArray(16).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }
        saves[token] = s
        return token
    }

    @Synchronized
    fun take(token: String?): Save? = token?.let { saves.remove(it) }
}

/** The responses shared by the service and [FillActivity]. */
object Fills {
    /** A browser's page domain, else the app's package; a browser without a domain gives nothing. */
    fun serviceOf(form: ParsedForm): FfiAutofillService? = when {
        form.webDomain != null -> FfiAutofillService.Site(form.webDomain!!)
        FormParser.isBrowser(form.packageName) || form.packageName.isEmpty() -> null
        else -> FfiAutofillService.App(form.packageName)
    }

    fun serviceText(s: FfiAutofillService) = when (s) {
        is FfiAutofillService.Site -> s.value
        is FfiAutofillService.App -> s.id
    }

    /** The site or the app's name, for titles. */
    fun label(c: Context, form: ParsedForm): String = form.webDomain?.removePrefix("www.") ?: runCatching {
        c.packageManager.getApplicationLabel(c.packageManager.getApplicationInfo(form.packageName, 0)).toString()
    }.getOrDefault(form.packageName)

    private fun t(c: Context, fr: String, en: String) = if (c.resources.configuration.locales[0].language == "fr") fr else en

    fun presentation(c: Context, title: String, subtitle: String?): RemoteViews = RemoteViews(c.packageName, R.layout.autofill_item).apply {
        setTextViewText(R.id.autofill_title, title)
        setTextViewText(R.id.autofill_subtitle, subtitle ?: "")
    }

    private var requestCode = 0

    private fun pending(c: Context, intent: Intent) =
        PendingIntent.getActivity(c, ++requestCode, intent, PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_CANCEL_CURRENT).intentSender

    /** The Logins to offer: the core's plan first, then the other candidates, six at most. */
    fun candidates(session: Session, form: ParsedForm, service: FfiAutofillService): List<FfiAutofillCandidate> {
        val request = if (form.otps.isNotEmpty() && form.passwords.isEmpty()) FfiAutofillRequest.ONE_TIME_CODE else FfiAutofillRequest.PASSWORD
        val all = session.autofillServiceCandidates(service, false, emptyList())
        val plan = runCatching { session.autofillServicePlan(service, request, emptyList()).itemIds }.getOrDefault(emptyList())
        val first = plan.mapNotNull { id -> all.firstOrNull { it.itemId == id } }
        return (first + all.filter { it !in first }).take(6)
    }

    @Suppress("DEPRECATION")
    private fun authDataset(c: Context, form: ParsedForm, title: String, subtitle: String?, intent: Intent): Dataset {
        val b = Dataset.Builder(presentation(c, title, subtitle))
        form.allIds.forEach { b.setValue(it, null) }
        b.setAuthentication(pending(c, intent))
        return b.build()
    }

    fun saveInfo(form: ParsedForm): SaveInfo? {
        if (form.passwords.isEmpty()) return null
        val type = SaveInfo.SAVE_DATA_TYPE_PASSWORD or (if (form.usernames.isNotEmpty()) SaveInfo.SAVE_DATA_TYPE_USERNAME else 0)
        return SaveInfo.Builder(type, form.passwords.toTypedArray()).apply {
            if (form.usernames.isNotEmpty()) setOptionalIds(form.usernames.toTypedArray())
            setFlags(SaveInfo.FLAG_SAVE_ON_ALL_VIEWS_INVISIBLE)
        }.build()
    }

    fun response(c: Context, form: ParsedForm, service: FfiAutofillService, session: Session): FillResponse? {
        val list = candidates(session, form, service)
        val b = FillResponse.Builder()
        list.forEach { cand ->
            val intent = Intent(c, FillActivity::class.java).setAction(FillActivity.ACTION_PICK)
                .putExtra(FillActivity.EXTRA_VAULT, cand.vaultId).putExtra(FillActivity.EXTRA_ITEM, cand.itemId)
            b.addDataset(authDataset(c, form, cand.title.ifBlank { cand.user }, cand.user.takeIf { it.isNotBlank() && it != cand.title } ?: cand.url, intent))
        }
        b.addDataset(authDataset(c, form, t(c, "Rechercher dans OnePass", "Search OnePass"), if (list.isEmpty()) t(c, "Aucun élément pour ce site.", "No items for this site.") else null,
            Intent(c, FillActivity::class.java).setAction(FillActivity.ACTION_SEARCH)))
        saveInfo(form)?.let { b.setSaveInfo(it) }
        return b.build()
    }

    /** Locked: one entry; [FillActivity] unlocks and answers with the full response. */
    fun lockedResponse(c: Context, form: ParsedForm): FillResponse {
        val b = FillResponse.Builder()
        b.setAuthentication(form.allIds.toTypedArray(), pending(c, Intent(c, FillActivity::class.java).setAction(FillActivity.ACTION_UNLOCK)),
            presentation(c, t(c, "Déverrouille OnePass", "Unlock OnePass"), t(c, "pour remplir ", "to fill ") + label(c, form)))
        saveInfo(form)?.let { b.setSaveInfo(it) }
        return b.build()
    }
}
