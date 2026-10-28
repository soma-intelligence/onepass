import CryptoKit
import Foundation
import OnePassCore

/// Which Watchtower findings deserve a notification, and which ones were already notified.
///
/// The memory is a set of 16 hex character prefixes of SHA-256(`check|item id`): enough to tell a
/// finding seen before from a new one, never an item id in clear in the preferences. The first
/// report only fills the memory, so turning notifications on never floods the user with what the
/// page already shows. A finding that goes away leaves the memory; if it comes back it alerts again.
public enum WatchtowerAlerts {
    /// Checks worth interrupting for, in the order of the notification text.
    public static let alertable = ["compromised", "breached_site", "provider_exposed", "expired", "expiring"]

    public struct Alert: Equatable, Sendable {
        public let check: String
        public let count: Int
        public init(check: String, count: Int) {
            self.check = check
            self.count = count
        }
    }

    static func fingerprint(check: String, itemID: String) -> String {
        let digest = SHA256.hash(data: Data("\(check)|\(itemID)".utf8))
        return digest.prefix(8).map { String(format: "%02x", $0) }.joined()
    }

    /// The new alertable findings of `report` against `remembered` (nil: never computed), and the
    /// memory to keep.
    public static func diff(
        _ report: FfiWatchtowerReport, remembered: Set<String>?
    ) -> (alerts: [Alert], memory: Set<String>) {
        var memory = Set<String>()
        var fresh: [String: Int] = [:]
        for check in report.checks where alertable.contains(check.check) {
            for id in check.itemIds {
                let print = fingerprint(check: check.check, itemID: id)
                memory.insert(print)
                if let remembered, !remembered.contains(print) { fresh[check.check, default: 0] += 1 }
            }
        }
        let alerts = alertable.compactMap { check in fresh[check].map { Alert(check: check, count: $0) } }
        return (alerts, memory)
    }

    /// The notification text: counts per check, never a title or a site (it shows on a locked screen).
    public static func body(for alerts: [Alert]) -> String {
        alerts.map { line(for: $0) }.joined(separator: " ")
    }

    static func line(for alert: Alert) -> String {
        let n = alert.count
        switch alert.check {
        case "compromised":
            return n == 1
                ? String(localized: "1 mot de passe apparaît dans une fuite.", bundle: VaultKitStrings.bundle)
                : String(localized: "\(n) mots de passe apparaissent dans des fuites.", bundle: VaultKitStrings.bundle)
        case "breached_site":
            return n == 1
                ? String(localized: "1 site a été piraté depuis ton dernier changement de mot de passe.", bundle: VaultKitStrings.bundle)
                : String(localized: "\(n) sites ont été piratés depuis ton dernier changement de mot de passe.", bundle: VaultKitStrings.bundle)
        case "provider_exposed":
            return n == 1
                ? String(localized: "1 compte de connexion est exposé.", bundle: VaultKitStrings.bundle)
                : String(localized: "\(n) comptes de connexion sont exposés.", bundle: VaultKitStrings.bundle)
        case "expired":
            return n == 1
                ? String(localized: "1 élément a expiré.", bundle: VaultKitStrings.bundle)
                : String(localized: "\(n) éléments ont expiré.", bundle: VaultKitStrings.bundle)
        default:
            return n == 1
                ? String(localized: "1 élément expire bientôt.", bundle: VaultKitStrings.bundle)
                : String(localized: "\(n) éléments expirent bientôt.", bundle: VaultKitStrings.bundle)
        }
    }
}

/// Per-item Watchtower exclusions (`FfiItem.watchtowerExclusions`): the core skips an excluded check
/// for that item.
public enum WatchtowerExclusions {
    public static func set(_ check: String, excluded: Bool, in ids: inout [String]) {
        if excluded {
            if !ids.contains(check) { ids.append(check) }
        } else {
            ids.removeAll { $0 == check }
        }
    }

    /// The checks that flagged `itemID` in `report`, sorted.
    public static func checks(of itemID: String, in report: FfiWatchtowerReport) -> [String] {
        report.checks.filter { $0.itemIds.contains(itemID) }.map(\.check).sorted()
    }
}
