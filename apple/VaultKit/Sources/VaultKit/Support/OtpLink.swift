import Foundation
import OnePassCore

/// `otpauth://` and `otpauth-migration://` links, opened by the system once OnePass is chosen in
/// Réglages > Général > Saisie auto et mots de passe > Codes de vérification (the camera, Safari or
/// another app hands the link over). The core parses them (`otp_link_accounts`); the link holds the
/// secret: never logged, never kept past the sheet that adds it.
public enum OtpLink {
    /// The URL schemes the app declares for verification codes (`CFBundleURLTypes`).
    public static let schemes: Set<String> = ["otpauth", "otpauth-migration"]

    /// A verification code link (not a `onepass://` link, not a web page).
    public static func handles(_ url: URL) -> Bool {
        guard let scheme = url.scheme?.lowercased() else { return false }
        return schemes.contains(scheme)
    }

    /// A scanned or pasted text that is a verification code link.
    public static func isLink(_ text: String) -> Bool {
        let lower = text.trimmingCharacters(in: .whitespacesAndNewlines).prefix(20).lowercased()
        return lower.hasPrefix("otpauth://") || lower.hasPrefix("otpauth-migration://")
    }

    /// One account per code: one for an `otpauth://totp/...` link, one or more for a Google
    /// Authenticator export. Throws for HOTP, a malformed link or anything else.
    public static func accounts(in link: String) throws -> [OtpLinkAccount] {
        try otpLinkAccounts(link: link).enumerated().map { index, account in
            OtpLinkAccount(index: index, issuer: account.issuer, account: account.account, uri: account.uri)
        }
    }
}

/// One code of a link: its names in clear, the canonical `otpauth://` URI (secret included) for the
/// `totp` field of a Login.
public struct OtpLinkAccount: Identifiable, Sendable, Equatable, CustomStringConvertible,
    CustomDebugStringConvertible
{
    public let index: Int
    public let issuer: String?
    public let account: String?
    /// The canonical URI, secret included: for the code preview and the item's `totp` field only,
    /// never logged.
    public let uri: String

    public var id: Int { index }

    init(index: Int, issuer: String?, account: String?, uri: String) {
        self.index = index
        self.issuer = issuer
        self.account = account
        self.uri = uri
    }

    /// Title of a new Login: the issuer, else the account.
    public var title: String {
        issuer ?? account ?? String(localized: "Code de vérification", bundle: VaultKitStrings.bundle)
    }

    /// Username of a new Login (required by the template): the account, else the issuer, else the title.
    public var username: String { account ?? issuer ?? title }

    /// The current code, for the preview.
    public func code(at date: Date = Date()) -> FfiTotpCode? {
        try? totpNow(secretOrUri: uri, unixSeconds: UInt64(max(0, date.timeIntervalSince1970)))
    }

    /// Logins that probably belong to this code, best first: the issuer in the title or the
    /// website, then the account as the subtitle (the username).
    public func suggestions(in logins: [FfiItemSummary]) -> [FfiItemSummary] {
        func norm(_ s: String) -> String {
            s.folding(options: [.caseInsensitive, .diacriticInsensitive], locale: nil)
                .filter { $0.isLetter || $0.isNumber }
        }
        let issuer = issuer.map(norm).flatMap { $0.isEmpty ? nil : $0 }
        let account = account.map { $0.lowercased() }
        func score(_ item: FfiItemSummary) -> Int {
            var score = 0
            if let issuer {
                if norm(item.title).contains(issuer) { score += 2 }
                if let url = item.primaryUrl, norm(url).contains(issuer) { score += 2 }
            }
            if let account, !account.isEmpty, item.subtitle.lowercased() == account { score += 1 }
            return score
        }
        let scored: [(item: FfiItemSummary, score: Int)] = logins.map { ($0, score($0)) }.filter { $0.1 > 0 }
        let sorted = scored.sorted { (a: (item: FfiItemSummary, score: Int), b: (item: FfiItemSummary, score: Int)) -> Bool in
            if a.score != b.score { return a.score > b.score }
            return a.item.title.localizedStandardCompare(b.item.title) == .orderedAscending
        }
        return sorted.map(\.item)
    }

    public var description: String { "OtpLinkAccount(\(issuer ?? "-"), \(account ?? "-"))" }
    public var debugDescription: String { description }
}

/// A request from outside the app that waits for the unlock (a code to copy, a verification code
/// link holding its secret) is dropped after 2 minutes, or at once if the clock moved back.
public enum PendingRequest {
    public static let lifetime: TimeInterval = 120

    public static func isExpired(queuedAt: Date, now: Date) -> Bool {
        let age = now.timeIntervalSince(queuedAt)
        return age < 0 || age > lifetime
    }
}

/// What the "Ajouter un code" sheet may do with an existing Login.
public enum OtpTarget: Equatable, Sendable {
    /// A `reprompt` Login: confirm the user (biometrics or master password) first.
    case confirmFirst
    /// The code can be written; `hasOtp` asks before replacing the current one.
    case ready(hasOtp: Bool)
}

extension VaultSession {
    /// The visible Logins, by title, for the "add a code" sheet (search included).
    public func otpCandidateLogins(query: String) -> [FfiItemSummary] {
        items(filter: .all, query: query, sort: .title).filter { $0.itemType == .login }
    }

    /// Where a code would go in an existing Login, read before anything of the item is shown. A
    /// `reprompt` Login says nothing (not even whether it has a code) until the user is confirmed,
    /// like the item page.
    public func otpTarget(itemID: String, vaultID: String, confirmed: Bool) async throws -> OtpTarget {
        let item = try await loadItem(vaultID: vaultID, itemID: itemID)
        guard item.itemType == .login else { throw VaultError.other(Self.notALogin) }
        if item.reprompt, !confirmed { return .confirmFirst }
        return .ready(hasOtp: Self.currentOtp(in: item) != nil)
    }

    /// Puts the code into the `totp` field of an existing Login. A previous, different code moves to
    /// a concealed custom field "Ancien code", so it stays recoverable. A `reprompt` Login is written
    /// only once the user is confirmed (`confirmed`, as for showing it). Returns the stored item.
    @discardableResult
    public func attachOtp(_ account: OtpLinkAccount, toItemID itemID: String, vaultID: String, confirmed: Bool)
        async throws -> FfiItem
    {
        var item = try await loadItem(vaultID: vaultID, itemID: itemID)
        guard item.itemType == .login else { throw VaultError.other(Self.notALogin) }
        guard !item.reprompt || confirmed else { throw VaultError.other(Self.confirmFirst) }
        if let previous = Self.currentOtp(in: item), previous != account.uri {
            var draft = ItemDraft(item: item)
            draft.addCustomField(kind: .concealed, label: Self.previousCodeLabel)
            if let s = draft.item.sections.firstIndex(where: { $0.id == ItemDraft.customSectionID }),
                let f = draft.item.sections[s].fields.indices.last
            {
                draft.item.sections[s].fields[f].value = .concealed(value: previous)
            }
            item = draft.item
        }
        Self.setOtp(account.uri, in: &item)
        return try await save(item)
    }

    /// A new Login with the code: the issuer as its title, the account as its username.
    @discardableResult
    public func createLogin(with account: OtpLinkAccount, vaultID: String) async throws -> FfiItem {
        var item = try newItem(type: .login, vaultID: vaultID)
        item.title = account.title
        for s in item.sections.indices {
            if let f = item.sections[s].fields.firstIndex(where: { $0.id == "username" }) {
                item.sections[s].fields[f].value = .text(value: account.username)
            }
        }
        Self.setOtp(account.uri, in: &item)
        return try await save(item)
    }

    private static let notALogin = String(
        localized: "Le code ne peut être ajouté qu'à un élément Login.", bundle: VaultKitStrings.bundle)
    private static let confirmFirst = String(
        localized: "Confirme d'abord ton identité pour modifier cet élément.", bundle: VaultKitStrings.bundle)
    /// The label of the field that keeps a replaced code (stored as written, like any label).
    static let previousCodeLabel = String(localized: "Ancien code", bundle: VaultKitStrings.bundle)

    /// The Login's current one-time code, if its `totp` field holds one.
    private static func currentOtp(in item: FfiItem) -> String? {
        let value = item.sections.lazy.flatMap(\.fields).first { $0.id == "totp" }?.value.text ?? ""
        return value.isEmpty ? nil : value
    }

    /// Sets the template's `totp` field; a Login without one gets it in its first section.
    private static func setOtp(_ uri: String, in item: inout FfiItem) {
        for s in item.sections.indices {
            if let f = item.sections[s].fields.firstIndex(where: { $0.id == "totp" }) {
                item.sections[s].fields[f].value = .otp(value: uri)
                return
            }
        }
        let field = FfiField(
            id: "totp", label: "TOTP", kind: .otp, value: .otp(value: uri), required: false, repeatable: false, autofill: true)
        if item.sections.isEmpty {
            item.sections = [FfiSection(id: "main", label: "", fields: [field])]
        } else {
            item.sections[0].fields.append(field)
        }
    }
}
