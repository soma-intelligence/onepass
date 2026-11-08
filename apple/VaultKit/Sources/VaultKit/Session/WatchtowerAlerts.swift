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
                ? String(localized: "session.n1PasswordAppearsIn", bundle: VaultKitStrings.bundle)
                : String(localized: "session.passwordsAppearInBreaches \(n)", bundle: VaultKitStrings.bundle)
        case "breached_site":
            return n == 1
                ? String(localized: "session.n1SiteWasBreached", bundle: VaultKitStrings.bundle)
                : String(localized: "session.sitesWereBreachedSince \(n)", bundle: VaultKitStrings.bundle)
        case "provider_exposed":
            return n == 1
                ? String(localized: "session.n1SignInAccount", bundle: VaultKitStrings.bundle)
                : String(localized: "session.signInAccountsExposed \(n)", bundle: VaultKitStrings.bundle)
        case "expired":
            return n == 1
                ? String(localized: "session.n1ItemHasExpired", bundle: VaultKitStrings.bundle)
                : String(localized: "session.itemsHaveExpired \(n)", bundle: VaultKitStrings.bundle)
        default:
            return n == 1
                ? String(localized: "session.n1ItemExpiresSoon", bundle: VaultKitStrings.bundle)
                : String(localized: "session.itemsExpireSoon \(n)", bundle: VaultKitStrings.bundle)
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

/// Whether a login's site is known to accept passkeys, for the "Ajouter une passkey" row of the
/// item detail.
public enum PasskeySupport {
    /// The Watchtower check of a login whose site is in the passkeys directory and that holds no
    /// passkey yet.
    public static let check = "passkey_available"

    /// True when the login already holds a passkey, or when the last Watchtower report flagged it
    /// `passkey_available`. The flag stands whether or not "Ignorer" hid the banner (exclusions
    /// only hide). No report yet: not known, so false; the editor still offers the row.
    public static func siteAccepts(_ item: FfiItem, report: FfiWatchtowerReport?) -> Bool {
        guard item.itemType == .login else { return false }
        let holdsOne = item.sections.contains { section in
            section.fields.contains { if case .passkey = $0.value { true } else { false } }
        }
        if holdsOne || item.loginMethods.contains(.passkey) { return true }
        guard let report else { return false }
        return WatchtowerExclusions.checks(of: item.id, in: report).contains(check)
    }
}
