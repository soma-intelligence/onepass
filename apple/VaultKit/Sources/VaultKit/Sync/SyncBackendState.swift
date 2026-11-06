import Foundation

/// A mailbox an account syncs with: the base URL as the signed home names it, the mailbox id (32
/// hex characters) and, for a self-host, the PEM of a CA trusted on top of the web roots.
public struct MailboxHome: Codable, Equatable, Hashable, Sendable {
    public var baseURL: URL
    public var mailboxID: String
    public var extraCAPEM: String?

    public init(baseURL: URL, mailboxID: String, extraCAPEM: String? = nil) {
        self.baseURL = baseURL
        self.mailboxID = mailboxID
        self.extraCAPEM = extraCAPEM
    }

    /// The endpoint the core's mailbox client talks to.
    public var endpoint: FfiMailboxEndpoint {
        FfiMailboxEndpoint(baseUrl: baseURL.absoluteString, extraCaPem: extraCAPEM)
    }

    /// The home as the account signs it.
    public var backend: FfiSyncBackend {
        .mailbox(baseUrl: baseURL.absoluteString, mailboxId: mailboxID)
    }
}

/// Where a new account keeps its encrypted vault (cross-platform spec D.2, D.3). Default: the
/// OnePass server hosted by Soma.
public enum SyncChoice: Codable, Equatable, Hashable, Sendable {
    case hosted
    case iCloud
    case selfHost(url: URL, extraCAPEM: String?)

    public static let `default`: SyncChoice = .hosted
}

/// Where this store's account syncs, as the app last decided it (store meta `sync.backend`). A
/// store from before the mailbox has none: it syncs with iCloud.
public enum SyncBackendState: Codable, Equatable, Sendable {
    case iCloud
    case mailbox(MailboxHome)
    /// A new account whose mailbox setup has not finished: the setup resumes at launch.
    case pendingSetup(SyncChoice)

    /// Store meta key (the handle namespaces it under `sync.`).
    static let metaKey = "backend"

    public static func read(store: SyncStoreHandle) async throws -> SyncBackendState {
        try await CoreThread.run { try readNow(store: store) }
    }

    /// `read` on the caller's thread: the app reads it once at launch, before the session exists.
    public static func readNow(store: SyncStoreHandle) throws -> SyncBackendState {
        let data = try store.meta(key: metaKey)
        guard let data, !data.isEmpty else { return .iCloud }
        return try JSONDecoder().decode(SyncBackendState.self, from: data)
    }

    public static func write(_ state: SyncBackendState, store: SyncStoreHandle) async throws {
        let data = try JSONEncoder().encode(state)
        try await CoreThread.run { try store.setMeta(key: metaKey, value: data) }
    }

    /// What the settings line names: "Serveur OnePass" for the hosted instance, the host of a
    /// self-host, "iCloud" otherwise.
    public func displayName(hosted: URL?) -> String {
        switch self {
        case .iCloud, .pendingSetup(.iCloud): "iCloud"
        case .mailbox(let home): MailboxEndpoints.displayName(home.baseURL, hosted: hosted)
        case .pendingSetup(.hosted): MailboxEndpoints.hostedName
        case .pendingSetup(.selfHost(let url, _)): MailboxEndpoints.displayName(url, hosted: hosted)
        }
    }
}
