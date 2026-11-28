package me.somalabs.onepass.autofill

import android.app.assist.AssistStructure
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId

/** What a field asks for. */
enum class Role { USERNAME, PASSWORD, NEW_PASSWORD, OTP, OTHER }

/**
 * Everything the form tells about one field, taken out of the view node so
 * [classify] stays a pure function (unit-tested on the JVM).
 */
data class Clue(
    val hints: List<String> = emptyList(),
    val inputType: Int = 0,
    val htmlTag: String? = null,
    val htmlType: String? = null,
    val htmlName: String? = null,
    val htmlAutocomplete: String? = null,
    val idEntry: String? = null,
    val hint: String? = null,
    val className: String? = null,
)

/**
 * Reads a login form out of an [AssistStructure]: the username, password and
 * one-time code fields, the web domain a browser reports (null in an app),
 * the app's package, and the typed values (for a save request).
 */
class ParsedForm(
    val packageName: String,
    val webDomain: String?,
    val usernames: List<AutofillId>,
    val passwords: List<AutofillId>,
    val otps: List<AutofillId>,
    val newPassword: Boolean,
    val usernameValue: String?,
    val passwordValue: String?,
) {
    val fillable get() = usernames.isNotEmpty() || passwords.isNotEmpty() || otps.isNotEmpty()
    val allIds get() = usernames + passwords + otps
}

object FormParser {
    private val userWords = listOf("user", "login", "email", "e-mail", "mail", "identifiant", "identifier", "account", "compte", "phone", "nom d'utilisateur", "username")
    private val passWords = listOf("pass", "pwd", "mot de passe", "motdepasse", "secret", "pin")
    private val otpWords = listOf("otp", "one-time", "onetime", "2fa", "totp", "verification code", "code de vérification", "one time", "authenticator", "mfa")
    private val newWords = listOf("new", "nouveau", "confirm", "register", "signup", "sign-up", "create")
    private val searchWords = listOf("search", "recherche", "query")

    /** The role of one field, from the strongest clue down (autofill hints, HTML, input type, names). */
    fun classify(c: Clue): Role {
        val hints = c.hints.map { it.lowercase() }
        if (hints.any { it == View.AUTOFILL_HINT_PASSWORD.lowercase() || it == "current-password" }) return Role.PASSWORD
        if (hints.any { it == "newpassword" || it == "new-password" }) return Role.NEW_PASSWORD
        if (hints.any { it == View.AUTOFILL_HINT_USERNAME.lowercase() || it == View.AUTOFILL_HINT_EMAIL_ADDRESS.lowercase() || it == "email" || it == "newusername" }) return Role.USERNAME
        if (hints.any { it.contains("otp") || it == "onetimecode" || it == "one-time-code" }) return Role.OTP

        val auto = c.htmlAutocomplete?.lowercase()
        if (auto != null) {
            if ("current-password" in auto) return Role.PASSWORD
            if ("new-password" in auto) return Role.NEW_PASSWORD
            if ("one-time-code" in auto) return Role.OTP
            if ("username" in auto || auto.split(' ').contains("email")) return Role.USERNAME
        }
        val htmlType = c.htmlType?.lowercase()
        if (c.htmlTag?.lowercase() == "input") {
            when (htmlType) {
                "password" -> return if (words(c).any { w -> newWords.any { it in w } }) Role.NEW_PASSWORD else Role.PASSWORD
                "email" -> return Role.USERNAME
                "hidden", "submit", "button", "checkbox", "radio", "search" -> return Role.OTHER
            }
        }

        val cls = c.inputType and InputType.TYPE_MASK_CLASS
        val variation = c.inputType and InputType.TYPE_MASK_VARIATION
        val passwordType = (cls == InputType.TYPE_CLASS_TEXT && (variation == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
            variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD || variation == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD)) ||
            (cls == InputType.TYPE_CLASS_NUMBER && variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD)
        val ws = words(c)
        if (ws.any { w -> searchWords.any { it in w } }) return Role.OTHER
        if (passwordType) {
            if (ws.any { w -> otpWords.any { it in w } }) return Role.OTP
            return if (ws.any { w -> newWords.any { it in w } }) Role.NEW_PASSWORD else Role.PASSWORD
        }
        if (cls == InputType.TYPE_CLASS_TEXT && (variation == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS || variation == InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS)) return Role.USERNAME
        if (ws.any { w -> otpWords.any { it in w } }) return Role.OTP
        if (ws.any { w -> passWords.any { it in w } } && cls != InputType.TYPE_CLASS_PHONE) return Role.PASSWORD
        if (ws.any { w -> userWords.any { it in w } }) return Role.USERNAME
        return Role.OTHER
    }

    private fun words(c: Clue) = listOfNotNull(c.htmlName, c.idEntry, c.hint).map { it.lowercase() }

    /** True for a node that takes typed text (an EditText or an HTML input). */
    private fun isInput(n: AssistStructure.ViewNode): Boolean {
        if (n.autofillType != View.AUTOFILL_TYPE_TEXT || n.autofillId == null) return false
        if (n.visibility != View.VISIBLE) return false
        val tag = n.htmlInfo?.tag?.lowercase()
        if (tag != null) return tag == "input" || tag == "textarea"
        return n.inputType != 0 || n.className?.contains("EditText") == true
    }

    private fun clue(n: AssistStructure.ViewNode): Clue {
        val attrs = n.htmlInfo?.attributes.orEmpty().associate { it.first.lowercase() to it.second }
        return Clue(
            hints = n.autofillHints?.toList().orEmpty(),
            inputType = n.inputType,
            htmlTag = n.htmlInfo?.tag,
            htmlType = attrs["type"],
            htmlName = listOfNotNull(attrs["name"], attrs["id"], attrs["placeholder"], attrs["aria-label"]).joinToString(" ").ifBlank { null },
            htmlAutocomplete = attrs["autocomplete"],
            idEntry = n.idEntry,
            hint = n.hint,
            className = n.className,
        )
    }

    fun parse(structure: AssistStructure): ParsedForm {
        val inputs = mutableListOf<Pair<AssistStructure.ViewNode, Role>>()
        var domain: String? = null
        fun walk(n: AssistStructure.ViewNode) {
            if (domain == null) n.webDomain?.takeIf { it.isNotBlank() }?.let { domain = it }
            if (isInput(n)) inputs += n to classify(clue(n))
            for (i in 0 until n.childCount) walk(n.getChildAt(i))
        }
        for (i in 0 until structure.windowNodeCount) walk(structure.getWindowNodeAt(i).rootViewNode)

        val users = inputs.filter { it.second == Role.USERNAME }.map { it.first }.toMutableList()
        val passwords = inputs.filter { it.second == Role.PASSWORD || it.second == Role.NEW_PASSWORD }.map { it.first }
        val otps = inputs.filter { it.second == Role.OTP }.map { it.first }
        // A password with no username field: the text field just before it holds the username.
        if (users.isEmpty() && passwords.isNotEmpty()) {
            val first = inputs.indexOfFirst { it.first === passwords.first() }
            inputs.subList(0, first).lastOrNull { it.second == Role.OTHER }?.let { users += it.first }
        }
        fun text(n: AssistStructure.ViewNode?) = n?.autofillValue?.takeIf { it.isText }?.textValue?.toString()?.takeIf { it.isNotEmpty() }
            ?: n?.text?.toString()?.takeIf { it.isNotEmpty() && n.autofillValue != null }
        return ParsedForm(
            packageName = structure.activityComponent?.packageName.orEmpty(),
            webDomain = domain,
            usernames = users.mapNotNull { it.autofillId },
            passwords = passwords.mapNotNull { it.autofillId },
            otps = otps.mapNotNull { it.autofillId },
            newPassword = inputs.any { it.second == Role.NEW_PASSWORD },
            usernameValue = text(users.firstOrNull()),
            passwordValue = text(passwords.firstOrNull()),
        )
    }

    /**
     * The service string the core matches: a browser's page domain, else the
     * app's package (the Login's `apps`). Browsers without a domain get nothing.
     */
    fun isBrowser(pkg: String) = pkg in BROWSERS

    val BROWSERS = setOf(
        "com.android.chrome", "com.chrome.beta", "com.chrome.dev", "com.chrome.canary", "org.chromium.chrome",
        "org.mozilla.firefox", "org.mozilla.firefox_beta", "org.mozilla.fenix", "org.mozilla.focus", "org.mozilla.klar",
        "com.microsoft.emmx", "com.brave.browser", "com.opera.browser", "com.opera.mini.native", "com.vivaldi.browser",
        "com.duckduckgo.mobile.android", "com.sec.android.app.sbrowser", "com.kiwibrowser.browser", "org.bromite.bromite",
        "app.vanadium.browser", "com.google.android.apps.chrome", "com.ecosia.android", "com.mi.globalbrowser",
    )
}
