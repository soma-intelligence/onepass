package me.somalabs.onepass.passkey

import android.annotation.TargetApi
import android.app.Activity
import android.content.Intent
import android.credentials.CreateCredentialException
import android.credentials.CreateCredentialResponse
import android.credentials.Credential
import android.credentials.GetCredentialException
import android.credentials.GetCredentialResponse
import android.os.Bundle
import android.service.credentials.BeginGetCredentialRequest
import android.service.credentials.CallingAppInfo
import android.service.credentials.CreateCredentialRequest
import android.service.credentials.CredentialProviderService
import android.service.credentials.GetCredentialRequest
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.LinearLayout
import android.widget.ScrollView
import java.util.concurrent.Executors
import me.somalabs.onepass.R
import me.somalabs.onepass.core.FfiAutofillService
import me.somalabs.onepass.core.FfiFieldType
import me.somalabs.onepass.core.FfiFieldValue
import me.somalabs.onepass.core.FfiItemType
import me.somalabs.onepass.core.FfiPasskeyCreation
import me.somalabs.onepass.core.OnePassException
import me.somalabs.onepass.core.Session
import me.somalabs.onepass.credentials.WebAuthn
import me.somalabs.onepass.fill.Unlocker
import me.somalabs.onepass.ui.Ios
import me.somalabs.onepass.vault.DeviceVault
import me.somalabs.onepass.vaultkit.core.CoreLoader

/**
 * What the Credential Manager opens from a Cleon entry: unlock, then sign
 * with a passkey, hand over a password, or save a new passkey or password
 * ("Enregistrer une passkey pour …"). Not exported; the PendingIntents carry
 * ids only, the request comes from the system.
 */
@TargetApi(34)
class PasskeyActivity : Activity() {
    private lateinit var ui: Ios
    private val worker = Executors.newSingleThreadExecutor()
    private val vault by lazy { DeviceVault.get(this) }
    private var unlocker: Unlocker? = null

    private fun t(fr: String, en: String) = Credentials.t(this, fr, en)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE == 0) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        CoreLoader.ensureLoaded()
        ui = Ios(this)
        vault.lockIfIdle()
        if (vault.session == null) {
            if (vault.state() != DeviceVault.State.LOCKED) return fail(t("Ouvre Cleon pour configurer ton coffre", "Open Cleon to set up your vault"))
            window.setBackgroundDrawable(android.graphics.drawable.ColorDrawable(ui.page))
            val u = Unlocker(this, ui, null)
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

    private fun fail(message: String) {
        val i = Intent()
        when (intent.action) {
            ACTION_CREATE_PASSKEY, ACTION_CREATE_PASSWORD ->
                i.putExtra(CredentialProviderService.EXTRA_CREATE_CREDENTIAL_EXCEPTION, CreateCredentialException(CreateCredentialException.TYPE_UNKNOWN, message))
            else -> i.putExtra(CredentialProviderService.EXTRA_GET_CREDENTIAL_EXCEPTION, GetCredentialException(GetCredentialException.TYPE_UNKNOWN, message))
        }
        setResult(RESULT_OK, i)
        finish()
    }

    private fun done(i: Intent) {
        setResult(RESULT_OK, i)
        finish()
    }

    private fun proceed() {
        val s = vault.session ?: return cancel()
        runCatching {
            when (intent.action) {
                ACTION_UNLOCK -> {
                    val req = intent.getParcelableExtra(CredentialProviderService.EXTRA_BEGIN_GET_CREDENTIAL_REQUEST, BeginGetCredentialRequest::class.java) ?: return cancel()
                    done(Intent().putExtra(CredentialProviderService.EXTRA_BEGIN_GET_CREDENTIAL_RESPONSE, Credentials.entries(this, s, req)))
                }
                ACTION_GET_PASSKEY -> assertion(s)
                ACTION_GET_PASSWORD -> password(s)
                ACTION_CREATE_PASSKEY -> createPasskey(s)
                ACTION_CREATE_PASSWORD -> createPassword(s)
                else -> cancel()
            }
        }.onFailure { fail(it.javaClass.simpleName) }
    }

    /** The origin of the request: the browser's page, or the app's signing key. */
    private fun origin(app: CallingAppInfo): String? = app.origin
        ?: app.signingInfo.apkContentsSigners.firstOrNull()?.toByteArray()?.let { WebAuthn.appOrigin(it) }

    // ---- sign in -------------------------------------------------------------------------------

    private fun assertion(s: Session) {
        val req = intent.getParcelableExtra(CredentialProviderService.EXTRA_GET_CREDENTIAL_REQUEST, GetCredentialRequest::class.java) ?: return cancel()
        val option = req.credentialOptions.firstOrNull { it.type == WebAuthn.TYPE_PUBLIC_KEY } ?: return cancel()
        val json = option.credentialRetrievalData.getString(WebAuthn.KEY_REQUEST_JSON) ?: return cancel()
        val parsed = WebAuthn.parseGet(json)
        val vaultId = intent.getStringExtra(EXTRA_VAULT) ?: return cancel()
        val itemId = intent.getStringExtra(EXTRA_ITEM) ?: return cancel()
        val credentialId = WebAuthn.unb64(intent.getStringExtra(EXTRA_CREDENTIAL) ?: return cancel())
        // A browser hashes its own client data; a native app's request gets ours.
        val given = option.credentialRetrievalData.getByteArray(WebAuthn.KEY_CLIENT_DATA_HASH)
        val clientData = if (given == null) WebAuthn.clientDataJson("webauthn.get", parsed.challenge, origin(req.callingAppInfo) ?: return cancel(), req.callingAppInfo.packageName) else null
        val hash = given ?: WebAuthn.sha256(clientData!!)
        worker.execute {
            val r = runCatching { s.passkeyAssertion(vaultId, itemId, credentialId, hash) }
            runCatching { s.noteAutofillServiceUse("$vaultId:$itemId", FfiAutofillService.Site(parsed.rpId), emptyList()) }
            runOnUiThread {
                r.onSuccess { a ->
                    val data = Bundle().apply {
                        putString(WebAuthn.KEY_AUTHENTICATION_RESPONSE_JSON, WebAuthn.assertionJson(a.credentialId, clientData, a.authenticatorData, a.signature, a.userHandle))
                        putString(WebAuthn.KEY_SUBTYPE, WebAuthn.SUBTYPE_PUBLIC_KEY)
                    }
                    done(Intent().putExtra(CredentialProviderService.EXTRA_GET_CREDENTIAL_RESPONSE, GetCredentialResponse(Credential(WebAuthn.TYPE_PUBLIC_KEY, data))))
                }.onFailure { fail(it.javaClass.simpleName) }
            }
        }
    }

    private fun password(s: Session) {
        val item = s.item(intent.getStringExtra(EXTRA_VAULT) ?: return cancel(), intent.getStringExtra(EXTRA_ITEM) ?: return cancel())
        val fields = item.sections.flatMap { it.fields }
        fun text(v: FfiFieldValue?) = when (v) { is FfiFieldValue.Text -> v.value; is FfiFieldValue.Email -> v.value; is FfiFieldValue.Password -> v.value; else -> null }
        val user = text((fields.firstOrNull { it.id == "username" } ?: fields.firstOrNull { it.kind == FfiFieldType.EMAIL })?.value).orEmpty()
        val pw = text(fields.firstOrNull { it.kind == FfiFieldType.PASSWORD }?.value) ?: return fail("no password")
        val data = Bundle().apply { putString(WebAuthn.KEY_ID, user); putString(WebAuthn.KEY_PASSWORD, pw) }
        done(Intent().putExtra(CredentialProviderService.EXTRA_GET_CREDENTIAL_RESPONSE, GetCredentialResponse(Credential(WebAuthn.TYPE_PASSWORD, data))))
    }

    // ---- save ----------------------------------------------------------------------------------

    private fun page(title: String, content: LinearLayout.() -> Unit) {
        window.setBackgroundDrawable(android.graphics.drawable.ColorDrawable(ui.page))
        val col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(0, ui.dp(48), 0, ui.dp(40)) }
        val bar = LinearLayout(this).apply { gravity = Gravity.CENTER_VERTICAL; setPadding(ui.dp(12), ui.dp(8), ui.dp(12), ui.dp(4)) }
        bar.addView(ui.text(t("Annuler", "Cancel"), 17f, ui.accent).apply { setPadding(ui.dp(8), ui.dp(8), ui.dp(8), ui.dp(8)); isClickable = true; setOnClickListener { cancel() } })
        bar.addView(View(this), LinearLayout.LayoutParams(0, 1, 1f))
        col.addView(bar)
        col.addView(ui.image(R.mipmap.ic_launcher, 64).apply { (layoutParams as LinearLayout.LayoutParams).gravity = Gravity.CENTER_HORIZONTAL })
        col.addView(ui.text(title, 22f, ui.label, 700).apply { gravity = Gravity.CENTER; setPadding(ui.dp(24), ui.dp(16), ui.dp(24), ui.dp(8)) })
        col.content()
        setContentView(ScrollView(this).apply { isFillViewport = true; setBackgroundColor(ui.page); addView(col) })
    }

    private fun vaultFor(s: Session): String? = intent.getStringExtra(EXTRA_VAULT) ?: runCatching { s.vaults().firstOrNull()?.id }.getOrNull()

    private fun createPasskey(s: Session) {
        val req = intent.getParcelableExtra(CredentialProviderService.EXTRA_CREATE_CREDENTIAL_REQUEST, CreateCredentialRequest::class.java) ?: return cancel()
        val json = req.data.getString(WebAuthn.KEY_REQUEST_JSON) ?: return cancel()
        val c = WebAuthn.parseCreate(json)
        val rpId = c.rpId.ifBlank { req.callingAppInfo.origin?.removePrefix("https://")?.substringBefore('/') ?: return cancel() }
        val vaultId = vaultFor(s) ?: return fail("no vault")
        val given = req.data.getByteArray(WebAuthn.KEY_CLIENT_DATA_HASH)
        val clientData = if (given == null) WebAuthn.clientDataJson("webauthn.create", c.challenge, origin(req.callingAppInfo) ?: return cancel(), req.callingAppInfo.packageName) else null
        val hash = given ?: WebAuthn.sha256(clientData!!)
        // A Login of this site with the same user name takes the passkey.
        val existing = runCatching { s.autofillServiceCandidates(FfiAutofillService.Site(rpId), false, emptyList()) }.getOrDefault(emptyList())
            .firstOrNull { it.vaultId == vaultId && it.user.equals(c.userName, true) }
        val vaultName = runCatching { s.vaults().firstOrNull { it.id == vaultId }?.meta?.name }.getOrNull() ?: "Cleon"
        page(t("Enregistrer une passkey pour $rpId", "Save a Passkey for $rpId")) {
            addView(ui.inset(ui.card(
                ui.row(title = c.userName.ifBlank { c.userDisplayName }, subtitle = c.rpName.ifBlank { rpId }, chevron = false),
                ui.row(title = t("Coffre", "Vault"), value = vaultName, chevron = false),
                existing?.let { ui.row(title = t("Ajouter à ", "Add to ") + it.title, chevron = false) },
            ), top = Ios.Space.L))
            addView(ui.footnote(t("La passkey reste dans ton coffre Cleon, chiffrée sur tes appareils.", "The passkey stays in your Cleon vault, encrypted on your devices.")))
            addView(ui.capsule(t("Enregistrer la passkey", "Save Passkey")) {
                worker.execute {
                    val r = runCatching {
                        s.createPasskey(FfiPasskeyCreation(vaultId, existing?.itemId, rpId, c.userName.ifBlank { c.userDisplayName }, c.userId, hash, c.excluded))
                    }
                    runOnUiThread {
                        r.onSuccess { reg ->
                            val data = Bundle().apply { putString(WebAuthn.KEY_REGISTRATION_RESPONSE_JSON, WebAuthn.registrationJson(reg.credentialId, clientData, reg.attestationObject)) }
                            done(Intent().putExtra(CredentialProviderService.EXTRA_CREATE_CREDENTIAL_RESPONSE, CreateCredentialResponse(data)))
                        }.onFailure {
                            if (it is OnePassException.PasskeyExcluded) {
                                done(Intent().putExtra(CredentialProviderService.EXTRA_CREATE_CREDENTIAL_EXCEPTION,
                                    CreateCredentialException("androidx.credentials.TYPE_CREATE_PUBLIC_KEY_CREDENTIAL_DOM_EXCEPTION/androidx.credentials.TYPE_INVALID_STATE_ERROR", "excluded")))
                            } else fail(it.javaClass.simpleName)
                        }
                    }
                }
            }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { setMargins(ui.dp(16), ui.dp(20), ui.dp(16), 0) })
        }
    }

    private fun createPassword(s: Session) {
        val req = intent.getParcelableExtra(CredentialProviderService.EXTRA_CREATE_CREDENTIAL_REQUEST, CreateCredentialRequest::class.java) ?: return cancel()
        val user = req.data.getString(WebAuthn.KEY_ID).orEmpty()
        val pw = req.data.getString(WebAuthn.KEY_PASSWORD) ?: return cancel()
        val pkg = req.callingAppInfo.packageName
        val vaultId = vaultFor(s) ?: return fail("no vault")
        val title = runCatching { packageManager.getApplicationLabel(packageManager.getApplicationInfo(pkg, 0)).toString() }.getOrDefault(pkg)
        page(t("Enregistrer dans Cleon", "Save in Cleon")) {
            addView(ui.inset(ui.card(
                ui.row(title = title, subtitle = user.ifBlank { null }, chevron = false),
                ui.row(title = t("mot de passe", "Password"), value = "••••••••••", chevron = false),
            ), top = Ios.Space.L))
            addView(ui.capsule(t("Enregistrer", "Save")) {
                worker.execute {
                    val r = runCatching {
                        val n = s.newItem(vaultId, FfiItemType.LOGIN, title)
                        n.sections = n.sections.map { sec ->
                            sec.copy(fields = sec.fields.map { f ->
                                when {
                                    f.id == "username" && user.isNotEmpty() -> f.copy(value = if (f.kind == FfiFieldType.EMAIL) FfiFieldValue.Email(user) else FfiFieldValue.Text(user))
                                    f.id == "password" -> f.copy(value = FfiFieldValue.Password(pw))
                                    else -> f
                                }
                            })
                        }
                        n.apps = listOf(pkg)
                        s.saveItem(n)
                    }
                    runOnUiThread {
                        r.onSuccess { done(Intent().putExtra(CredentialProviderService.EXTRA_CREATE_CREDENTIAL_RESPONSE, CreateCredentialResponse(Bundle()))) }
                            .onFailure { fail(it.javaClass.simpleName) }
                    }
                }
            }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { setMargins(ui.dp(16), ui.dp(20), ui.dp(16), 0) })
        }
    }

    companion object {
        const val ACTION_UNLOCK = "me.somalabs.onepass.passkey.UNLOCK"
        const val ACTION_GET_PASSKEY = "me.somalabs.onepass.passkey.GET_PASSKEY"
        const val ACTION_GET_PASSWORD = "me.somalabs.onepass.passkey.GET_PASSWORD"
        const val ACTION_CREATE_PASSKEY = "me.somalabs.onepass.passkey.CREATE_PASSKEY"
        const val ACTION_CREATE_PASSWORD = "me.somalabs.onepass.passkey.CREATE_PASSWORD"
        const val EXTRA_VAULT = "vault"
        const val EXTRA_ITEM = "item"
        const val EXTRA_CREDENTIAL = "credential"
    }
}
