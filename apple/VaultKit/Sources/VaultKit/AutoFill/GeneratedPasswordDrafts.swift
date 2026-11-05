import Foundation

/// A generated password the system reported as filled (`generatedPasswordFilled`, iOS 26.2+) and that
/// no Login holds yet (G3). The account may already exist on the site with it: it must never be lost
/// when the save request that should follow never comes (multi-step form, in-app browser, app killed).
public struct GeneratedPasswordDraft: Codable, Sendable, Equatable {
    public var service: String
    public var serviceIsApp: Bool
    public var displayName: String?
    public var user: String
    public var password: String
    public var title: String?
    public var createdAt: Date

    public init(_ save: SavePasswordRequest, at date: Date) {
        service = save.service
        serviceIsApp = save.serviceIsApp
        displayName = save.displayName
        user = save.user
        password = save.password
        title = save.title
        createdAt = date
    }

    /// The draft as the save request it stands for.
    public var saveRequest: SavePasswordRequest {
        SavePasswordRequest(
            service: service, serviceIsApp: serviceIsApp, user: user, password: password, title: title,
            event: .formDidDisappear, displayName: displayName)
    }
}

/// The pending generated passwords of one account, sealed in the shared keychain (this device only,
/// readable while unlocked: `KeychainStore.write`), never in the settings or a log. Only a password
/// the system says was filled is kept (a proposal never used is never stored). A draft leaves when a
/// Login holds that password (save sheet, silent save, or the next unlocked provider request writes
/// it), when the user cancels the save sheet of that password, or after `lifetime`.
public struct GeneratedPasswordDrafts: Sendable {
    /// Long enough for a sign-up finished later; short enough that a forgotten one does not linger.
    public static let lifetime: TimeInterval = 7 * 24 * 3600
    /// At most this many drafts (the oldest go first).
    static let limit = 5

    private let keychain: any KeychainStore
    private let key: String

    /// `scope`: the account's settings scope (nil for the primary account).
    public init(keychain: any KeychainStore, scope: String?) {
        self.keychain = keychain
        key = "autofill.generated-drafts" + (scope.map { ".\($0)" } ?? "")
    }

    public init(environment: VaultEnvironment) {
        self.init(keychain: environment.keychain, scope: environment.settings.scope)
    }

    /// The live drafts, oldest first. Expired ones are dropped from the keychain.
    public func load(now: Date) -> [GeneratedPasswordDraft] {
        guard let data = try? keychain.read(key),
            let all = try? JSONDecoder().decode([GeneratedPasswordDraft].self, from: data)
        else { return [] }
        let live = all.filter { now.timeIntervalSince($0.createdAt) < Self.lifetime && $0.createdAt <= now }
        if live.count != all.count { write(live) }
        return live
    }

    /// Keeps `draft`, replacing one of the same service, user and password.
    public func add(_ draft: GeneratedPasswordDraft, now: Date) {
        var all = load(now: now).filter { !Self.same($0, draft) }
        all.append(draft)
        write(Array(all.suffix(Self.limit)))
    }

    /// Drops the drafts of `password` (for `service`, or every service when nil).
    public func remove(password: String, service: String? = nil, now: Date) {
        let all = load(now: now)
        let kept = all.filter { $0.password != password || (service != nil && $0.service != service) }
        if kept.count != all.count { write(kept) }
    }

    private static func same(_ a: GeneratedPasswordDraft, _ b: GeneratedPasswordDraft) -> Bool {
        a.service == b.service && a.serviceIsApp == b.serviceIsApp && a.user == b.user && a.password == b.password
    }

    private func write(_ drafts: [GeneratedPasswordDraft]) {
        if drafts.isEmpty {
            try? keychain.delete(key)
        } else if let data = try? JSONEncoder().encode(drafts) {
            try? keychain.write(key, data)
        }
    }
}
