import Foundation

/// The texts the Profil computes from the account, sync, settings and Watchtower (spec
/// 2026-11-14-profile-account-security, sections 3.2 and 3.3). Pure: the views pass the values in.
public enum ProfileFacts {
    /// A Watchtower check with findings, as the Security card lists it.
    public struct Issue: Equatable, Sendable {
        public let check: String
        public let findings: UInt32

        public init(check: String, findings: UInt32) {
            self.check = check
            self.findings = findings
        }
    }

    /// "0123…cdef": the first and last four characters of a long account ID; a short one as is,
    /// nil without one.
    public static func shortID(_ id: String?) -> String? {
        guard let id, !id.isEmpty else { return nil }
        guard id.count > 12 else { return id }
        return "\(id.prefix(4))\u{2026}\(id.suffix(4))"
    }

    /// "À jour · il y a 3 min": the status, then the last sync when it is known.
    public static func syncLine(_ status: SyncStatus, now: Date, locale: Locale = .current) -> String {
        guard case .idle(let lastSync?) = status else { return status.label }
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .short
        formatter.locale = locale
        return "\(status.label) \u{00B7} \(formatter.localizedString(for: lastSync, relativeTo: now))"
    }

    /// "Face ID · 5 minutes", or the auto-lock delay alone when biometrics are off or not allowed.
    public static func unlockLine(biometry: String?, delay: AutoLockDelay) -> String {
        guard let biometry else { return delay.label }
        return "\(biometry) \u{00B7} \(delay.label)"
    }

    /// The Watchtower checks that are problems, most serious first: what the Security card lists.
    /// A site offering a passkey or 2FA (`passkey_available`, `missing_2fa`) is a suggestion, left out.
    public static let problemChecks = [
        "compromised", "breached_site", "provider_exposed", "reused", "weak", "insecure_url",
    ]

    /// The checks of `among` with findings, most findings first, ties in the order of `among`.
    public static func topIssues(_ report: FfiWatchtowerReport?, among checks: [String], limit: Int = 2) -> [Issue] {
        guard let report else { return [] }
        let rank = Dictionary(checks.enumerated().map { ($1, $0) }, uniquingKeysWith: { first, _ in first })
        return report.checks
            .filter { $0.findings > 0 && rank[$0.check] != nil }
            .sorted { ($0.findings, rank[$1.check]!) > ($1.findings, rank[$0.check]!) }
            .prefix(limit)
            .map { Issue(check: $0.check, findings: $0.findings) }
    }

    /// "Personnel", "Professionnel", "Géré par une organisation".
    public static func kindLabel(_ kind: FfiAccountKind) -> String {
        switch kind {
        case .personal: String(localized: "profile.facts.kind.personal", bundle: VaultKitStrings.bundle)
        case .business: String(localized: "profile.facts.kind.business", bundle: VaultKitStrings.bundle)
        case .managed: String(localized: "profile.facts.kind.managed", bundle: VaultKitStrings.bundle)
        }
    }
}
