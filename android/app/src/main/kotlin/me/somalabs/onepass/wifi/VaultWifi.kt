package me.somalabs.onepass.wifi

import me.somalabs.onepass.core.FfiWifiNetwork
import me.somalabs.onepass.core.FfiWifiSecurity
import me.somalabs.onepass.core.Session

/**
 * The vault side of automatic Wi-Fi: which networks to hand Android, as the
 * core's shared model chooses them (`Session.wifiNetworks`: SSID plus a WPA2
 * or WPA3 personal key, never open, WEP or enterprise, one per SSID, trash
 * and archive left out), so Android installs what the other platforms do.
 *
 * The vault screens call [opened] after each unlock and [changed] after each
 * change (save, trash, restore, archive, move, remote commit), [locked] on
 * lock. Travel Mode needs nothing here: the items it hides are not in the
 * session.
 */
object VaultWifi {
    fun networks(session: Session, hiddenVaultIds: List<String> = emptyList()): List<WifiNetwork> =
        session.wifiNetworks(hiddenVaultIds).networks.map(::network)

    fun network(n: FfiWifiNetwork): WifiNetwork =
        WifiNetwork(
            ssid = n.ssid,
            passphrase = n.psk,
            security = when (n.security) {
                FfiWifiSecurity.WPA2_PERSONAL -> WifiSecurity.WPA2
                FfiWifiSecurity.WPA3_PERSONAL -> WifiSecurity.WPA3
            },
            hidden = n.hidden,
            itemId = n.itemId,
            fingerprint = n.fingerprint,
        )

    /** The vault is open: its networks go to Android (on the Wi-Fi thread). */
    fun opened(automation: WifiAutomation, session: Session) {
        automation.networkSource = { networks(session) }
        automation.refresh()
    }

    fun changed(automation: WifiAutomation) {
        automation.refresh()
    }

    /** The vault locked: the suggestions stay, the source goes. */
    fun locked(automation: WifiAutomation) {
        automation.networkSource = null
    }
}
