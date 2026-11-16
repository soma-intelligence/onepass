import Foundation
import OnePassCore

/// What a login's site offers to set up, from the last Watchtower report: two-factor
/// authentication (`missing_2fa`) or a passkey (`passkey_available`), each with where to do it.
/// The site facts come from the signed site pack through `FfiWatchtowerCheck.siteLinks`; without
/// a report, or without a link for the item, there is no offer (never faked).
public struct SiteSetupOffer: Equatable, Sendable {
    public enum Kind: String, Sendable {
        case twoFactor = "missing_2fa"
        case passkey = "passkey_available"
    }

    public enum Action: Equatable, Sendable {
        /// The site's own settings page for this feature.
        case openSettings(URL)
        /// The site's documentation (2FA only, when the pack has no settings page).
        case seeHow(URL)
        /// The site's W3C passkey enrollment page, looked up when the user asks, else its home.
        case findPasskeyPage(host: String)
    }

    public let kind: Kind
    public let itemID: String
    /// The item host that matched the pack, which may not be the item's primary website.
    public let host: String
    public let action: Action
    /// The pack carries a setup recipe. Carried for the guided journey; it never changes `action`.
    public let hasRecipe: Bool

    /// The offers for an item's detail, two-factor first, then passkey. Empty for a non-login, a
    /// trashed or archived item, a check excluded for the item, or a login that already has the
    /// method (a code for two-factor, a passkey for passkey).
    public static func offers(for item: FfiItem, report: FfiWatchtowerReport?) -> [SiteSetupOffer] {
        guard item.itemType == .login, item.trashedAt == nil, !item.archived else { return [] }
        let kinds: [Kind] = [.twoFactor, .passkey]
        return kinds.compactMap { kind in
            guard !item.watchtowerExclusions.contains(kind.rawValue), !has(kind, item) else { return nil }
            return offer(kind: kind, itemID: item.id, report: report)
        }
    }

    /// The offer of one finding, from the report alone (Watchtower rows, no item at hand).
    public static func offer(kind: Kind, itemID: String, report: FfiWatchtowerReport?) -> SiteSetupOffer? {
        guard let check = report?.checks.first(where: { $0.check == kind.rawValue }),
            let link = check.siteLinks.first(where: { $0.itemId == itemID })
        else { return nil }
        let action: Action
        if let settings = https(link.settingsUrl) {
            action = .openSettings(settings)
        } else if kind == .twoFactor {
            guard let help = https(link.helpUrl) else { return nil }
            action = .seeHow(help)
        } else {
            action = .findPasskeyPage(host: link.host)
        }
        return SiteSetupOffer(kind: kind, itemID: itemID, host: link.host, action: action, hasRecipe: link.hasRecipe)
    }

    /// Only an https address is opened; anything else counts as absent.
    private static func https(_ raw: String?) -> URL? {
        guard let raw, let url = URL(string: raw), url.scheme?.lowercased() == "https", url.host() != nil else {
            return nil
        }
        return url
    }

    /// The login already has the method: a non-empty one-time code for two-factor (as the core
    /// sees it), a passkey for passkey.
    private static func has(_ kind: Kind, _ item: FfiItem) -> Bool {
        let values = item.sections.flatMap(\.fields).map(\.value)
        switch kind {
        case .twoFactor:
            return values.contains { value in
                if case .otp(let secret) = value { !secret.trimmingCharacters(in: .whitespaces).isEmpty } else { false }
            }
        case .passkey:
            return item.loginMethods.contains(.passkey)
                || values.contains { if case .passkey = $0 { true } else { false } }
        }
    }
}
