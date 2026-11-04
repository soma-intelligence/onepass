package me.somalabs.onepass.wifi

import android.content.Context
import android.net.wifi.WifiManager
import android.net.wifi.WifiNetworkSuggestion
import android.os.Build
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** [SuggestionPort] on the real WifiManager (Android 10 and later). */
class AndroidSuggestionPort(context: Context) : SuggestionPort {
    private val wifi: WifiManager = context.applicationContext.getSystemService(WifiManager::class.java)

    override val replacesInPlace: Boolean = Build.VERSION.SDK_INT >= Build.VERSION_CODES.R

    override fun installedSsids(): Set<String>? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return null
        return try {
            // Quotes stripped in case a release adds them: a mismatch would rebuild at each sync.
            wifi.networkSuggestions.mapNotNull { it.ssid?.removeSurrounding("\"") }.toSet()
        } catch (e: SecurityException) {
            null
        }
    }

    override fun add(networks: List<WifiNetwork>): PortResult {
        val suggestions = try {
            networks.map { build(it, it.passphrase) }
        } catch (e: IllegalArgumentException) {
            // A passphrase Android finds invalid: no message, it may quote the input.
            return PortResult.Refused("invalid network")
        }
        val code = call { wifi.addNetworkSuggestions(suggestions) }
        if (code == WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_DUPLICATE) {
            // Android 10 holds an older copy OnePass lost track of: replace it.
            remove(networks.map { it.key })
            return status(call { wifi.addNetworkSuggestions(suggestions) })
        }
        return status(code)
    }

    override fun remove(keys: List<NetworkKey>): PortResult {
        // Android matches a suggestion by SSID and security type, not by passphrase.
        val suggestions = keys.map { build(WifiNetwork(it.ssid, REMOVAL_PLACEHOLDER, it.security, false, "", ""), REMOVAL_PLACEHOLDER) }
        return removal(
            call {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    // Android 13: a network in use stays up until the phone leaves it,
                    // so a vault glitch (partial sync, hidden vault) never cuts a call.
                    wifi.removeNetworkSuggestions(suggestions, WifiManager.ACTION_REMOVE_SUGGESTION_LINGER)
                } else {
                    wifi.removeNetworkSuggestions(suggestions)
                }
            },
        )
    }

    // An empty list removes every suggestion of the app.
    override fun removeAll(): PortResult = removal(call { wifi.removeNetworkSuggestions(emptyList()) })

    /** Removing what Android no longer holds already reached the goal. */
    private fun removal(code: Int): PortResult =
        if (code == WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_REMOVE_INVALID) PortResult.Ok else status(code)

    /**
     * Android 12 and later report the approval only through a listener, which
     * answers with the current state as soon as it is registered. Called on the
     * sync thread, never the main one.
     */
    override fun approval(): SuggestionApproval {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return SuggestionApproval.UNKNOWN
        val latch = CountDownLatch(1)
        val status = AtomicInteger(WifiManager.STATUS_SUGGESTION_APPROVAL_UNKNOWN)
        val listener = WifiManager.SuggestionUserApprovalStatusListener { code ->
            status.set(code)
            latch.countDown()
        }
        try {
            wifi.addSuggestionUserApprovalStatusListener({ it.run() }, listener)
            latch.await(2, TimeUnit.SECONDS)
        } catch (e: SecurityException) {
            return SuggestionApproval.UNKNOWN
        } finally {
            try {
                wifi.removeSuggestionUserApprovalStatusListener(listener)
            } catch (e: RuntimeException) {
                // Not registered: nothing to undo.
            }
        }
        return when (status.get()) {
            WifiManager.STATUS_SUGGESTION_APPROVAL_APPROVED_BY_USER,
            WifiManager.STATUS_SUGGESTION_APPROVAL_APPROVED_BY_CARRIER_PRIVILEGE,
            -> SuggestionApproval.APPROVED
            WifiManager.STATUS_SUGGESTION_APPROVAL_REJECTED_BY_USER -> SuggestionApproval.REJECTED
            WifiManager.STATUS_SUGGESTION_APPROVAL_PENDING -> SuggestionApproval.PENDING
            else -> SuggestionApproval.UNKNOWN
        }
    }

    private fun build(network: WifiNetwork, passphrase: String): WifiNetworkSuggestion {
        val builder = WifiNetworkSuggestion.Builder().setSsid(network.ssid)
        when (network.security) {
            WifiSecurity.WPA2 -> builder.setWpa2Passphrase(passphrase)
            WifiSecurity.WPA3 -> builder.setWpa3Passphrase(passphrase)
        }
        return builder.setIsHiddenSsid(network.hidden).build()
    }

    private inline fun call(block: () -> Int): Int =
        try {
            block()
        } catch (e: SecurityException) {
            STATUS_SECURITY
        } catch (e: IllegalArgumentException) {
            STATUS_INVALID
        }

    private fun status(code: Int): PortResult =
        if (code == WifiManager.STATUS_NETWORK_SUGGESTIONS_SUCCESS) PortResult.Ok else PortResult.Refused(reasonOf(code))

    private fun reasonOf(code: Int): String = when (code) {
        WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_INTERNAL -> "internal"
        WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_APP_DISALLOWED -> "app disallowed"
        WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_DUPLICATE -> "duplicate"
        WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_EXCEEDS_MAX_PER_APP -> "too many networks"
        WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_REMOVE_INVALID -> "not installed"
        WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_NOT_ALLOWED -> "not allowed"
        WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_INVALID -> "invalid network"
        WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_RESTRICTED_BY_ADMIN -> "restricted by admin"
        STATUS_SECURITY -> "permission"
        STATUS_INVALID -> "invalid network"
        else -> "status $code"
    }

    private companion object {
        const val REMOVAL_PLACEHOLDER = "onepass-removal"
        const val STATUS_SECURITY = -1001
        const val STATUS_INVALID = -1002
    }
}
