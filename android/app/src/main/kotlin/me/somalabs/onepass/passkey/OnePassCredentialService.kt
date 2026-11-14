package me.somalabs.onepass.passkey

import android.annotation.TargetApi
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.credentials.ClearCredentialStateException
import android.credentials.CreateCredentialException
import android.credentials.GetCredentialException
import android.graphics.drawable.Icon
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import android.service.credentials.Action
import android.service.credentials.BeginCreateCredentialRequest
import android.service.credentials.BeginCreateCredentialResponse
import android.service.credentials.BeginGetCredentialRequest
import android.service.credentials.BeginGetCredentialResponse
import android.service.credentials.ClearCredentialStateRequest
import android.service.credentials.CreateEntry
import android.service.credentials.CredentialEntry
import android.service.credentials.CredentialProviderService
import me.somalabs.onepass.R
import me.somalabs.onepass.core.FfiAutofillService
import me.somalabs.onepass.core.Session
import me.somalabs.onepass.credentials.WebAuthn
import me.somalabs.onepass.vault.DeviceVault
import me.somalabs.onepass.vaultkit.core.CoreLoader

/**
 * OnePass in Android's Credential Manager (Android 14+), as the passkey and
 * password provider (iPhone: the AutoFill extension's passkeys). The selector
 * lists the Logins' passkeys for the relying party and the passwords for the
 * calling app; picking one, or "Déverrouille OnePass" when locked, opens
 * [PasskeyActivity], which signs with the core (`passkey_assertion`) or
 * creates the passkey (`create_passkey`). The private keys never leave the
 * core.
 */
@TargetApi(34)
class OnePassCredentialService : CredentialProviderService() {
    override fun onBeginGetCredential(request: BeginGetCredentialRequest, cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>) {
        val r = runCatching {
            CoreLoader.ensureLoaded()
            val vault = DeviceVault.get(this)
            vault.lockIfIdle()
            val s = vault.session
            if (s == null) {
                val b = BeginGetCredentialResponse.Builder()
                if (vault.state() == DeviceVault.State.LOCKED) {
                    val i = Intent(this, PasskeyActivity::class.java).setAction(PasskeyActivity.ACTION_UNLOCK)
                    b.addAuthenticationAction(Action(WebAuthn.authenticationSlice(Credentials.t(this, "Déverrouille OnePass", "Unlock OnePass"), Credentials.pending(this, i))))
                }
                b.build()
            } else Credentials.entries(this, s, request)
        }
        r.onSuccess { callback.onResult(it) }.onFailure { callback.onResult(BeginGetCredentialResponse.Builder().build()) }
    }

    override fun onBeginCreateCredential(request: BeginCreateCredentialRequest, cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>) {
        if (request.type != WebAuthn.TYPE_PUBLIC_KEY && request.type != WebAuthn.TYPE_PASSWORD) {
            return callback.onError(CreateCredentialException(CreateCredentialException.TYPE_NO_CREATE_OPTIONS, "unsupported"))
        }
        val r = runCatching {
            CoreLoader.ensureLoaded()
            val vault = DeviceVault.get(this)
            if (vault.state() == DeviceVault.State.EMPTY) return@runCatching BeginCreateCredentialResponse.Builder().build()
            // The vaults are named only while unlocked; locked, one entry ("OnePass") unlocks first.
            val vaults = runCatching { vault.session?.vaults() }.getOrNull().orEmpty()
            val b = BeginCreateCredentialResponse.Builder()
            val icon = Icon.createWithResource(this, R.mipmap.ic_launcher)
            val note = if (request.type == WebAuthn.TYPE_PUBLIC_KEY) Credentials.t(this, "La passkey reste dans ton coffre OnePass, chiffrée sur tes appareils.",
                "The passkey stays in your OnePass vault, encrypted on your devices.") else null
            val action = if (request.type == WebAuthn.TYPE_PUBLIC_KEY) PasskeyActivity.ACTION_CREATE_PASSKEY else PasskeyActivity.ACTION_CREATE_PASSWORD
            if (vaults.isEmpty()) {
                b.addCreateEntry(CreateEntry(WebAuthn.createSlice("OnePass", note, icon, Credentials.pending(this, Intent(this, PasskeyActivity::class.java).setAction(action)))))
            } else vaults.forEach { v ->
                val i = Intent(this, PasskeyActivity::class.java).setAction(action).putExtra(PasskeyActivity.EXTRA_VAULT, v.id)
                b.addCreateEntry(CreateEntry(WebAuthn.createSlice(v.meta.name, note, icon, Credentials.pending(this, i))))
            }
            b.build()
        }
        r.onSuccess { callback.onResult(it) }.onFailure { callback.onError(CreateCredentialException(CreateCredentialException.TYPE_UNKNOWN, it.javaClass.simpleName)) }
    }

    override fun onClearCredentialState(request: ClearCredentialStateRequest, cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void, ClearCredentialStateException>) {
        callback.onResult(null)
    }
}

/** What the service and [PasskeyActivity] share. */
@TargetApi(34)
object Credentials {
    fun t(c: Context, fr: String, en: String) = if (c.resources.configuration.locales[0].language == "fr") fr else en

    private var code = 0

    fun pending(c: Context, i: Intent): PendingIntent =
        PendingIntent.getActivity(c, ++code, i, PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_CANCEL_CURRENT)

    /** The passkeys for the relying party of each passkey option, the passwords of the calling app. */
    fun entries(c: Context, s: Session, request: BeginGetCredentialRequest): BeginGetCredentialResponse {
        val b = BeginGetCredentialResponse.Builder()
        val icon = Icon.createWithResource(c, R.mipmap.ic_launcher)
        val caller = request.callingAppInfo?.packageName
        for (option in request.beginGetCredentialOptions) {
            when (option.type) {
                WebAuthn.TYPE_PUBLIC_KEY -> {
                    val json = option.candidateQueryData.getString(WebAuthn.KEY_REQUEST_JSON) ?: continue
                    val req = runCatching { WebAuthn.parseGet(json) }.getOrNull() ?: continue
                    if (req.rpId.isBlank()) continue
                    val cands = runCatching { s.autofillServiceCandidates(FfiAutofillService.Site(req.rpId), false, emptyList()) }.getOrDefault(emptyList())
                    for (cand in cands) for (pk in cand.passkeys) {
                        if (!pk.rpId.equals(req.rpId, true)) continue
                        if (req.allowed.isNotEmpty() && req.allowed.none { it.contentEquals(pk.credentialId) }) continue
                        val i = Intent(c, PasskeyActivity::class.java).setAction(PasskeyActivity.ACTION_GET_PASSKEY)
                            .putExtra(PasskeyActivity.EXTRA_VAULT, cand.vaultId).putExtra(PasskeyActivity.EXTRA_ITEM, cand.itemId)
                            .putExtra(PasskeyActivity.EXTRA_CREDENTIAL, WebAuthn.b64(pk.credentialId))
                        b.addCredentialEntry(CredentialEntry(option, WebAuthn.credentialSlice(WebAuthn.TYPE_PUBLIC_KEY, option.id, pk.userName.ifBlank { cand.title },
                            cand.title, "Passkey", icon, pending(c, i))))
                    }
                }
                WebAuthn.TYPE_PASSWORD -> {
                    val pkg = caller ?: continue
                    val cands = runCatching { s.autofillServiceCandidates(FfiAutofillService.App(pkg), false, emptyList()) }.getOrDefault(emptyList())
                    for (cand in cands.filter { it.hasPassword }) {
                        val i = Intent(c, PasskeyActivity::class.java).setAction(PasskeyActivity.ACTION_GET_PASSWORD)
                            .putExtra(PasskeyActivity.EXTRA_VAULT, cand.vaultId).putExtra(PasskeyActivity.EXTRA_ITEM, cand.itemId)
                        b.addCredentialEntry(CredentialEntry(option, WebAuthn.credentialSlice(WebAuthn.TYPE_PASSWORD, option.id, cand.user.ifBlank { cand.title },
                            cand.title, t(c, "Mot de passe", "Password"), icon, pending(c, i))))
                    }
                }
            }
        }
        return b.build()
    }
}
