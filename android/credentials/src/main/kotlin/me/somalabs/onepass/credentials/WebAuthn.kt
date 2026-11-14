package me.somalabs.onepass.credentials

import android.app.slice.Slice
import android.app.slice.SliceSpec
import android.app.PendingIntent
import android.graphics.drawable.Icon
import android.net.Uri
import java.security.MessageDigest
import java.util.Base64
import org.json.JSONArray
import org.json.JSONObject

/**
 * The WebAuthn side of Android's Credential Manager, without AndroidX: the
 * request and response JSON of a passkey, the client data a native app's
 * request lacks, and the entry slices the system selector reads (the layout
 * androidx.credentials writes, keys copied from the platform's
 * CredentialManager UI).
 */
object WebAuthn {
    const val TYPE_PUBLIC_KEY = "androidx.credentials.TYPE_PUBLIC_KEY_CREDENTIAL"
    const val TYPE_PASSWORD = "android.credentials.TYPE_PASSWORD_CREDENTIAL"
    const val KEY_REQUEST_JSON = "androidx.credentials.BUNDLE_KEY_REQUEST_JSON"
    const val KEY_CLIENT_DATA_HASH = "androidx.credentials.BUNDLE_KEY_CLIENT_DATA_HASH"
    const val KEY_AUTHENTICATION_RESPONSE_JSON = "androidx.credentials.BUNDLE_KEY_AUTHENTICATION_RESPONSE_JSON"
    const val KEY_REGISTRATION_RESPONSE_JSON = "androidx.credentials.BUNDLE_KEY_REGISTRATION_RESPONSE_JSON"
    const val KEY_SUBTYPE = "androidx.credentials.BUNDLE_KEY_SUBTYPE"
    const val SUBTYPE_PUBLIC_KEY = "androidx.credentials.BUNDLE_VALUE_SUBTYPE_PUBLIC_KEY_CREDENTIAL"
    const val SUBTYPE_CREATE_PUBLIC_KEY = "androidx.credentials.BUNDLE_VALUE_SUBTYPE_CREATE_PUBLIC_KEY_CREDENTIAL_REQUEST"
    const val KEY_ID = "androidx.credentials.BUNDLE_KEY_ID"
    const val KEY_PASSWORD = "androidx.credentials.BUNDLE_KEY_PASSWORD"

    fun b64(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    fun unb64(s: String): ByteArray = Base64.getUrlDecoder().decode(s.trim().trimEnd('=').replace('+', '-').replace('/', '_'))
    fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

    /** "android:apk-key-hash:…", the origin of a native app's request (its signing certificate). */
    fun appOrigin(signingCert: ByteArray) = "android:apk-key-hash:" + b64(sha256(signingCert))

    class GetRequest(val rpId: String, val challenge: String, val allowed: List<ByteArray>)

    fun parseGet(json: String): GetRequest {
        val o = JSONObject(json)
        val allow = o.optJSONArray("allowCredentials") ?: JSONArray()
        return GetRequest(o.optString("rpId"), o.getString("challenge"),
            (0 until allow.length()).mapNotNull { allow.optJSONObject(it)?.optString("id")?.takeIf { s -> s.isNotEmpty() }?.let(::unb64) })
    }

    class CreateRequest(val rpId: String, val rpName: String, val userId: ByteArray, val userName: String, val userDisplayName: String, val challenge: String, val excluded: List<ByteArray>)

    fun parseCreate(json: String): CreateRequest {
        val o = JSONObject(json)
        val rp = o.getJSONObject("rp")
        val user = o.getJSONObject("user")
        val ex = o.optJSONArray("excludeCredentials") ?: JSONArray()
        return CreateRequest(rp.optString("id"), rp.optString("name"), unb64(user.getString("id")), user.optString("name"),
            user.optString("displayName"), o.getString("challenge"),
            (0 until ex.length()).mapNotNull { ex.optJSONObject(it)?.optString("id")?.takeIf { s -> s.isNotEmpty() }?.let(::unb64) })
    }

    /** The client data a browser would have built, for a native app's request. */
    fun clientDataJson(type: String, challenge: String, origin: String, packageName: String?): ByteArray {
        val o = JSONObject().put("type", type).put("challenge", challenge).put("origin", origin).put("crossOrigin", false)
        packageName?.let { o.put("androidPackageName", it) }
        return o.toString().toByteArray()
    }

    fun assertionJson(credentialId: ByteArray, clientData: ByteArray?, authenticatorData: ByteArray, signature: ByteArray, userHandle: ByteArray): String {
        val r = JSONObject()
            .put("clientDataJSON", clientData?.let(::b64) ?: "")
            .put("authenticatorData", b64(authenticatorData))
            .put("signature", b64(signature))
        if (userHandle.isNotEmpty()) r.put("userHandle", b64(userHandle))
        return JSONObject().put("id", b64(credentialId)).put("rawId", b64(credentialId)).put("type", "public-key")
            .put("authenticatorAttachment", "platform").put("response", r).put("clientExtensionResults", JSONObject()).toString()
    }

    fun registrationJson(credentialId: ByteArray, clientData: ByteArray?, attestationObject: ByteArray): String {
        val r = JSONObject()
            .put("clientDataJSON", clientData?.let(::b64) ?: "")
            .put("attestationObject", b64(attestationObject))
            .put("transports", JSONArray().put("internal").put("hybrid"))
        return JSONObject().put("id", b64(credentialId)).put("rawId", b64(credentialId)).put("type", "public-key")
            .put("authenticatorAttachment", "platform").put("response", r).put("clientExtensionResults", JSONObject()).toString()
    }

    // ---- entry slices --------------------------------------------------------------------------

    private const val ENTRY = "androidx.credentials.provider.credentialEntry."
    private const val CREATE = "androidx.credentials.provider.createEntry."
    private const val AUTH = "androidx.credentials.provider.authenticationAction."

    /** A credential in the selector: title (the account), subtitle, the type's name. */
    fun credentialSlice(type: String, optionId: String, title: String, subtitle: String?, typeName: String, icon: Icon, intent: PendingIntent): Slice {
        val b = Slice.Builder(Uri.EMPTY, SliceSpec(type, 1))
            .addText(typeName, null, listOf(ENTRY + "SLICE_HINT_TYPE_DISPLAY_NAME"))
            .addText(title, null, listOf(ENTRY + "SLICE_HINT_USER_NAME"))
            .addText(subtitle, null, listOf(ENTRY + "SLICE_HINT_CREDENTIAL_TYPE_DISPLAY_NAME"))
            .addText("false", null, listOf(ENTRY + "SLICE_HINT_AUTO_ALLOWED"))
            .addText(optionId, null, listOf(ENTRY + "SLICE_HINT_OPTION_ID"))
            .addIcon(icon, null, listOf(ENTRY + "SLICE_HINT_PROFILE_ICON"))
        b.addAction(intent, Slice.Builder(b).addHints(listOf(ENTRY + "SLICE_HINT_PENDING_INTENT")).build(), null)
        return b.build()
    }

    /** "Déverrouille OnePass" when the vault is locked. */
    fun authenticationSlice(title: String, intent: PendingIntent): Slice {
        val b = Slice.Builder(Uri.EMPTY, SliceSpec("AuthenticationAction", 0))
            .addText(title, null, listOf(AUTH + "SLICE_HINT_TITLE"))
        b.addAction(intent, Slice.Builder(b).addHints(listOf(AUTH + "SLICE_HINT_PENDING_INTENT")).build(), null)
        return b.build()
    }

    /** Where a new passkey or password goes: the vault's name. */
    fun createSlice(accountName: String, note: String?, icon: Icon, intent: PendingIntent): Slice {
        val b = Slice.Builder(Uri.EMPTY, SliceSpec("CreateEntry", 1))
            .addText(accountName, null, listOf(CREATE + "SLICE_HINT_USER_PROVIDER_ACCOUNT_NAME"))
            .addIcon(icon, null, listOf(CREATE + "SLICE_HINT_PROFILE_ICON"))
            .addText("false", null, listOf(CREATE + "SLICE_HINT_AUTO_SELECT_ALLOWED"))
        note?.let { b.addText(it, null, listOf(CREATE + "SLICE_HINT_NOTE")) }
        b.addAction(intent, Slice.Builder(b).addHints(listOf(CREATE + "SLICE_HINT_PENDING_INTENT")).build(), null)
        return b.build()
    }
}
