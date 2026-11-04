#if os(iOS)
import Foundation
import NetworkExtension
import VaultKit

/// iPhone and iPad: each network becomes a persistent NEHotspotConfiguration (joinOnce false).
/// iOS asks once per network ("OnePass souhaite rejoindre le réseau..."): that question belongs to
/// the system and cannot be skipped. The batch stops at the first "no" or transient error, so a
/// user who dismisses is not asked again in a row. Needs the Hotspot Configuration entitlement.
struct HotspotInstaller: WifiInstaller {
    func install(_ networks: [WifiNetwork]) async -> [(WifiNetwork, WifiInstallOutcome)] {
        var out: [(WifiNetwork, WifiInstallOutcome)] = []
        for network in networks {
            let configuration = NEHotspotConfiguration(ssid: network.ssid, passphrase: network.password, isWEP: false)
            configuration.joinOnce = false
            configuration.hidden = network.hidden
            let outcome: WifiInstallOutcome
            do {
                try await NEHotspotConfigurationManager.shared.apply(configuration)
                outcome = .installed
            } catch {
                outcome = Self.outcome(of: error)
            }
            out.append((network, outcome))
            if outcome == .declined || outcome == .failed { break }
        }
        return out
    }

    /// NEHotspotConfigurationError codes, by meaning.
    static func outcome(of error: Error) -> WifiInstallOutcome {
        let e = error as NSError
        guard e.domain == NEHotspotConfigurationErrorDomain,
            let code = NEHotspotConfigurationError(rawValue: e.code)
        else { return .failed }
        switch code {
        case .alreadyAssociated:
            return .installed
        case .userDenied, .userUnauthorized:
            return .declined
        case .invalid, .invalidSSID, .invalidWPAPassphrase, .invalidWEPPassphrase, .invalidEAPSettings,
            .invalidHS20Settings, .invalidHS20DomainName, .joinOnceNotSupported, .invalidSSIDPrefix, .systemDenied:
            return .rejected
        default:
            // internal, pending, systemConfiguration, unknown, applicationIsNotInForeground
            return .failed
        }
    }
}
#endif
