package me.somalabs.onepass

import android.annotation.TargetApi
import android.app.Activity
import android.credentials.CreateCredentialException
import android.credentials.CreateCredentialRequest
import android.credentials.CreateCredentialResponse
import android.credentials.CredentialManager
import android.credentials.CredentialOption
import android.credentials.GetCredentialException
import android.credentials.GetCredentialRequest
import android.credentials.GetCredentialResponse
import android.os.Bundle
import android.os.OutcomeReceiver
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import java.security.MessageDigest
import java.security.SecureRandom
import me.somalabs.onepass.credentials.WebAuthn
import org.json.JSONObject

/**
 * Debug builds only: a relying party for "passkeys.onepass.test" that asks
 * Android's Credential Manager to create then use a passkey, to drive the
 * Cleon provider on the emulator. It shows what came back (sizes and the
 * relying party hash check, never a secret).
 */
@TargetApi(34)
class PasskeyDemoActivity : Activity() {
    private lateinit var out: TextView
    private val rp = "passkeys.onepass.test"

    private fun challenge() = WebAuthn.b64(ByteArray(32).also { SecureRandom().nextBytes(it) })

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(48, 200, 48, 48) }
        col.addView(TextView(this).apply { text = "Passkey demo ($rp)"; textSize = 22f })
        col.addView(Button(this).apply { text = "Create passkey"; setOnClickListener { create() } })
        col.addView(Button(this).apply { text = "Sign in with passkey"; setOnClickListener { get() } })
        out = TextView(this).apply { textSize = 15f; setPadding(0, 32, 0, 0) }
        col.addView(out)
        setContentView(col)
    }

    private fun create() {
        val json = JSONObject().put("challenge", challenge())
            .put("rp", JSONObject().put("id", rp).put("name", "Cleon Test"))
            .put("user", JSONObject().put("id", WebAuthn.b64("user-42".toByteArray())).put("name", "bob@onepass.test").put("displayName", "Bob"))
            .put("pubKeyCredParams", org.json.JSONArray().put(JSONObject().put("type", "public-key").put("alg", -7)))
            .put("authenticatorSelection", JSONObject().put("residentKey", "required").put("userVerification", "required")).toString()
        val display = Bundle().apply {
            putCharSequence("androidx.credentials.BUNDLE_KEY_USER_ID", "bob@onepass.test")
            putCharSequence("androidx.credentials.BUNDLE_KEY_USER_DISPLAY_NAME", "Bob")
        }
        val data = Bundle().apply {
            putString(WebAuthn.KEY_REQUEST_JSON, json)
            putString(WebAuthn.KEY_SUBTYPE, WebAuthn.SUBTYPE_CREATE_PUBLIC_KEY)
            putBundle("androidx.credentials.BUNDLE_KEY_REQUEST_DISPLAY_INFO", display)
        }
        val req = CreateCredentialRequest.Builder(WebAuthn.TYPE_PUBLIC_KEY, data, data).setAlwaysSendAppInfoToProvider(true).build()
        getSystemService(CredentialManager::class.java).createCredential(this, req, null, mainExecutor,
            object : OutcomeReceiver<CreateCredentialResponse, CreateCredentialException> {
                override fun onResult(r: CreateCredentialResponse) {
                    val o = JSONObject(r.data.getString(WebAuthn.KEY_REGISTRATION_RESPONSE_JSON) ?: "{}")
                    out.text = "CREATED id=${o.optString("id").take(12)}… attestationObject=${WebAuthn.unb64(o.getJSONObject("response").getString("attestationObject")).size} bytes"
                }
                override fun onError(e: CreateCredentialException) { out.text = "CREATE ERROR ${e.type}: ${e.message}" }
            })
    }

    private fun get() {
        val json = JSONObject().put("challenge", challenge()).put("rpId", rp).put("userVerification", "required").toString()
        val data = Bundle().apply {
            putString(WebAuthn.KEY_REQUEST_JSON, json)
            putString(WebAuthn.KEY_SUBTYPE, "androidx.credentials.BUNDLE_VALUE_SUBTYPE_GET_PUBLIC_KEY_CREDENTIAL_OPTION")
        }
        val req = GetCredentialRequest.Builder(Bundle()).addCredentialOption(CredentialOption.Builder(WebAuthn.TYPE_PUBLIC_KEY, data, data).build()).build()
        getSystemService(CredentialManager::class.java).getCredential(this, req, null, mainExecutor,
            object : OutcomeReceiver<GetCredentialResponse, GetCredentialException> {
                override fun onResult(r: GetCredentialResponse) {
                    val o = JSONObject(r.credential.data.getString(WebAuthn.KEY_AUTHENTICATION_RESPONSE_JSON) ?: "{}")
                    val resp = o.getJSONObject("response")
                    val authData = WebAuthn.unb64(resp.getString("authenticatorData"))
                    val rpHash = MessageDigest.getInstance("SHA-256").digest(rp.toByteArray())
                    val rpOk = authData.size >= 37 && authData.copyOfRange(0, 32).contentEquals(rpHash)
                    val flags = if (authData.size > 32) authData[32].toInt() and 0xff else 0
                    out.text = "SIGNED IN id=${o.optString("id").take(12)}… rpIdHash ok=$rpOk UP=${flags and 1 != 0} UV=${flags and 4 != 0} " +
                        "signature=${WebAuthn.unb64(resp.getString("signature")).size} bytes user=${String(WebAuthn.unb64(resp.optString("userHandle")))}"
                }
                override fun onError(e: GetCredentialException) { out.text = "GET ERROR ${e.type}: ${e.message}" }
            })
    }
}
