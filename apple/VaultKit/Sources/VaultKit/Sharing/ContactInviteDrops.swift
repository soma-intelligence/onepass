import Foundation
import os
import Synchronization

/// The drops of a remote contact invitation (sharing spec 13.9): the invitee's reply and the
/// inviter's answer, each spread over a drop of its own on the server the link names (plan 4
/// ruling: one sealed half measures over 128 KiB, more than one 64 KiB slot). Written once, read
/// until complete, deleted when used. A drop id is never logged.
public protocol InviteDrops: Sendable {
    func put(rdv: Data, part: FfiInvitePart, bytes: Data, server: URL) async throws
    /// `nil` until the half is all there.
    func get(rdv: Data, part: FfiInvitePart, server: URL) async throws -> Data?
    func delete(rdv: Data, part: FfiInvitePart, server: URL) async throws
}

/// Where the drops of an invitation live: the server the link names
/// (`onepass://contact/<host>#...`), else the Soma instance.
public enum InviteServer {
    static let linkPrefix = "onepass://contact/"
    static let mailboxPath = "/functions/v1/mailbox"

    /// The server of `link`, or `hosted` when the link names none (or names a host that does not
    /// pass `MailboxEndpoints.validate`).
    public static func url(forLink link: String, hosted: URL) -> URL {
        let text = link.trimmingCharacters(in: .whitespacesAndNewlines)
        guard text.hasPrefix(linkPrefix) else { return hosted }
        let rest = text.dropFirst(linkPrefix.count)
        guard let hash = rest.firstIndex(of: "#") else { return hosted }
        let host = String(rest[..<hash])
        guard !host.isEmpty, let url = URL(string: "https://\(host)\(mailboxPath)"),
              MailboxEndpoints.validate(url, allowHTTP: false)
        else { return hosted }
        return url
    }

    /// The host to put in a new link: none for the Soma instance.
    public static func linkHost(for server: URL, hosted: URL) -> String? {
        server == hosted ? nil : server.host()
    }
}

/// `InviteDrops` over the core's `invite_put`, `invite_get` and `invite_delete`.
public struct ContactInviteDrops: InviteDrops {
    private let extraCaPem: String?
    private let log: @Sendable (String) -> Void

    private static let logger = Logger(subsystem: "me.somalabs.onepass", category: "contact-invite")

    /// `log`: where the drop events go (os_log by default; tests capture them).
    public init(extraCaPem: String? = nil, log: (@Sendable (String) -> Void)? = nil) {
        self.extraCaPem = extraCaPem
        self.log = log ?? { Self.logger.notice("\($0, privacy: .public)") }
    }

    public func put(rdv: Data, part: FfiInvitePart, bytes: Data, server: URL) async throws {
        let ca = extraCaPem
        do {
            try await CoreThread.run {
                try invitePut(baseUrl: server.absoluteString, rdvId: rdv, part: part, bytes: bytes, extraCaPem: ca)
            }
            log("invite \(Self.name(part)) written (\(bytes.count) bytes)")
        } catch {
            log("invite \(Self.name(part)) not written")
            throw error
        }
    }

    public func get(rdv: Data, part: FfiInvitePart, server: URL) async throws -> Data? {
        let ca = extraCaPem
        let got = try await CoreThread.run {
            try inviteGet(baseUrl: server.absoluteString, rdvId: rdv, part: part, extraCaPem: ca)
        }
        log("invite \(Self.name(part)) \(got == nil ? "not there yet" : "read")")
        return got
    }

    public func delete(rdv: Data, part: FfiInvitePart, server: URL) async throws {
        let ca = extraCaPem
        try await CoreThread.run {
            try inviteDelete(baseUrl: server.absoluteString, rdvId: rdv, part: part, extraCaPem: ca)
        }
        log("invite \(Self.name(part)) deleted")
    }

    static func name(_ part: FfiInvitePart) -> String {
        switch part {
        case .reply: "reply"
        case .answer: "answer"
        }
    }
}

/// `InviteDrops` in memory, for tests and previews: write once, like the server.
public final class InMemoryInviteDrops: InviteDrops {
    private struct Key: Hashable {
        let server: URL
        let rdv: Data
        let part: String
    }
    private let drops = Mutex<[Key: Data]>([:])

    public init() {}

    public func put(rdv: Data, part: FfiInvitePart, bytes: Data, server: URL) async throws {
        let key = Key(server: server, rdv: rdv, part: ContactInviteDrops.name(part))
        try drops.withLock { d in
            if let old = d[key] {
                if old == bytes { return }
                throw OnePassError.Conflict
            }
            d[key] = bytes
        }
    }

    public func get(rdv: Data, part: FfiInvitePart, server: URL) async throws -> Data? {
        drops.withLock { $0[Key(server: server, rdv: rdv, part: ContactInviteDrops.name(part))] }
    }

    public func delete(rdv: Data, part: FfiInvitePart, server: URL) async throws {
        _ = drops.withLock { $0.removeValue(forKey: Key(server: server, rdv: rdv, part: ContactInviteDrops.name(part))) }
    }

    /// Tests: the servers written to.
    public var servers: Set<URL> { drops.withLock { Set($0.keys.map(\.server)) } }
}
