package me.somalabs.onepass.wifi

/**
 * A router item as read from the vault: the fields of the `router` template
 * (`ssid`, `wifi_password`, `security`, `hidden`, `guest_ssid`,
 * `guest_password`), plus what decides whether the item still counts.
 *
 * [usable] is false for an item in the trash, archived, or hidden by Travel
 * Mode: its networks leave the device like a deleted item's.
 */
data class RouterRecord(
    val itemId: String,
    val ssid: String,
    val password: String,
    val security: String,
    val hidden: String,
    val guestSsid: String = "",
    val guestPassword: String = "",
    val updatedAt: Long = 0,
    val usable: Boolean = true,
) {
    override fun toString(): String =
        "RouterRecord(itemId=$itemId, ssid=$ssid, security=$security, hidden=$hidden, " +
            "guestSsid=$guestSsid, updatedAt=$updatedAt, usable=$usable)"
}

/** The two personal security types an Android suggestion can carry. */
enum class WifiSecurity { WPA2, WPA3 }

/** What Android keys a suggestion by: one per SSID and security type. */
data class NetworkKey(val ssid: String, val security: WifiSecurity) {
    /** Stable text form for the ledger: security, a tab, the SSID. */
    fun encode(): String = "${security.name}\t$ssid"

    companion object {
        fun decode(text: String): NetworkKey? {
            val tab = text.indexOf('\t')
            if (tab <= 0) return null
            val security = WifiSecurity.entries.firstOrNull { it.name == text.substring(0, tab) } ?: return null
            val ssid = text.substring(tab + 1)
            return if (ssid.isEmpty()) null else NetworkKey(ssid, security)
        }
    }
}

/** One network OnePass hands to Android. The passphrase never shows in logs. */
data class WifiNetwork(
    val ssid: String,
    val passphrase: String,
    val security: WifiSecurity,
    val hidden: Boolean,
    /** The vault item it comes from. */
    val itemId: String,
) {
    val key: NetworkKey get() = NetworkKey(ssid, security)

    override fun toString(): String =
        "WifiNetwork(ssid=$ssid, security=$security, hidden=$hidden, itemId=$itemId, passphrase=[redacted])"
}

/**
 * Which router items become suggestions.
 *
 * Kept: a WPA2 or WPA3 personal network with an SSID and a passphrase Android
 * accepts (WPA, WPA2, WPA2/WPA3 and an empty security with a password count as
 * WPA2: a WPA2 suggestion joins a transition-mode router too).
 * Left out, on purpose: open networks and WEP (anyone can stand up a copy of
 * them, and OnePass would then send the phone to it: the evil twin), enterprise
 * networks (802.1X needs a CA and a domain to be safe, which the item does not
 * carry), and any security text OnePass does not recognise.
 */
object WifiSelection {
    /** An SSID is at most 32 bytes. */
    private const val MAX_SSID_BYTES = 32

    fun select(records: List<RouterRecord>): List<WifiNetwork> {
        // The most recently edited item wins when two describe the same network.
        val byKey = LinkedHashMap<NetworkKey, Pair<WifiNetwork, Long>>()
        for (record in records) {
            if (!record.usable) continue
            val security = securityOf(record.security, record.password) ?: continue
            val hidden = isYes(record.hidden)
            val candidates = listOf(
                network(record.ssid, record.password, security, hidden, record.itemId),
                // The guest network of the same router, same security; never hidden.
                network(record.guestSsid, record.guestPassword, security, false, record.itemId),
            )
            for (candidate in candidates.filterNotNull()) {
                val existing = byKey[candidate.key]
                if (existing == null || record.updatedAt > existing.second) {
                    byKey[candidate.key] = candidate to record.updatedAt
                }
            }
        }
        return byKey.values.map { it.first }.sortedWith(compareBy({ it.ssid }, { it.security }))
    }

    /** The suggestion security of a router's `security` text, or null to leave it out. */
    fun securityOf(security: String, password: String): WifiSecurity? {
        val s = security.trim().uppercase()
        if (ENTERPRISE_MARKERS.any { s.contains(it) }) return null
        if (s.contains("WEP")) return null
        if (OPEN_VALUES.contains(s)) return null
        return when {
            s.isEmpty() -> if (password.isEmpty()) null else WifiSecurity.WPA2
            // WPA2/WPA3 transition: a WPA2 suggestion joins either side.
            s.contains("WPA2") -> WifiSecurity.WPA2
            s.contains("WPA3") || s.contains("SAE") -> WifiSecurity.WPA3
            s.contains("WPA") -> WifiSecurity.WPA2
            else -> null
        }
    }

    /** Whether Android accepts this passphrase for the security type. */
    fun isValidPassphrase(passphrase: String, security: WifiSecurity): Boolean {
        val printableAscii = passphrase.all { it in ' '..'~' }
        return when (security) {
            // 8 to 63 printable ASCII characters, or the 64 hex digits of a raw PSK.
            WifiSecurity.WPA2 ->
                (printableAscii && passphrase.length in 8..63) ||
                    (passphrase.length == 64 && passphrase.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' })
            // SAE takes any length; Android asks for ASCII and caps at 128 here.
            WifiSecurity.WPA3 -> printableAscii && passphrase.length in 8..128
        }
    }

    private fun network(
        ssid: String,
        passphrase: String,
        security: WifiSecurity,
        hidden: Boolean,
        itemId: String,
    ): WifiNetwork? {
        if (ssid.isBlank() || ssid.toByteArray(Charsets.UTF_8).size > MAX_SSID_BYTES) return null
        if (!isValidPassphrase(passphrase, security)) return null
        return WifiNetwork(ssid, passphrase, security, hidden, itemId)
    }

    private fun isYes(value: String): Boolean = value.trim().lowercase() in setOf("oui", "yes", "true", "1")

    private val OPEN_VALUES = setOf("OUVERT", "OPEN", "NONE", "AUCUNE", "NOPASS")
    private val ENTERPRISE_MARKERS = listOf("ENTERPRISE", "ENTREPRISE", "EAP", "802.1X", "8021X", "RADIUS")
}
