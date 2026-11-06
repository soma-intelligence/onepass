import Foundation

/// The contact pair's mailbox made during a verification (sharing spec 13.5, decision 16): by the
/// side the core names (`creates_contact_zone`), before anything is pinned. It needs the network; a
/// failure pins nothing and the flow says so with `ContactZoneError.offline`.
public enum ContactZoneError: Error, Equatable, Sendable {
    case offline

    /// The text of spec 13.5 for a verification that cannot make the pair's mailbox with `name`.
    public func message(name: String) -> String {
        String(localized: "sharing.contact.offline \(name)", bundle: VaultKitStrings.bundle)
    }
}

/// Makes a pair mailbox and returns the signed offer for the verification session.
public protocol ContactZoneCreating: Sendable {
    func offer(for peerCard: Data, session: Session) async throws -> Data
}

/// `ContactZoneCreating` over `ZoneSyncHandle.contact_zone_create`.
public struct ContactZoneCreator: ContactZoneCreating {
    public let handle: ZoneSyncHandle
    private let now: @Sendable () -> Date

    public init(handle: ZoneSyncHandle, now: @escaping @Sendable () -> Date = { Date() }) {
        self.handle = handle
        self.now = now
    }

    public func offer(for peerCard: Data, session: Session) async throws -> Data {
        let (handle, stamp) = (handle, Int64(now().timeIntervalSince1970))
        do {
            return try await CoreThread.run {
                try handle.contactZoneCreate(session: session, peerCard: peerCard, now: stamp)
            }
        } catch OnePassError.MailboxUnavailable, OnePassError.Forbidden, OnePassError.ClockSkew {
            throw ContactZoneError.offline
        } catch is URLError {
            throw ContactZoneError.offline
        }
    }
}

/// The order decision 16 sets for the side that makes the pair's mailbox: the offer first, then the
/// pin. When the offer fails, `pin` never runs and the error is `ContactZoneError.offline` (or the
/// creator's own).
public enum ContactZoneStep {
    public static func offerThenPin<T: Sendable>(
        creator: any ContactZoneCreating, peerCard: Data, session: Session,
        pin: @Sendable (Data) async throws -> T
    ) async throws -> T {
        let offer = try await creator.offer(for: peerCard, session: session)
        return try await pin(offer)
    }
}
