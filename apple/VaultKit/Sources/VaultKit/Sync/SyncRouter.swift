import Foundation
import Synchronization

/// A sync coordinator the router can hand over to: the iCloud `SyncCoordinator` or the mailbox
/// `MailboxSyncCoordinator`.
public protocol RoutableSync: SyncTrigger {
    func statusUpdates() async -> AsyncStream<SyncStatus>
    func remoteChanges() async -> AsyncStream<Void>
}

extension SyncCoordinator: RoutableSync {}
extension MailboxSyncCoordinator: RoutableSync {}

/// The `SyncTrigger` the vault session talks to, forwarding to the account's current coordinator.
/// A migration or a follower switches it to another coordinator without a new session: the round
/// in progress on the old one ends first, the old one loses the session, the new one gets it. The
/// status and change streams go on across a switch.
public actor SyncRouter: SyncTrigger {
    private var current: any RoutableSync
    private var session: Session?
    private var generation = 0
    private var statusContinuations: [UUID: AsyncStream<SyncStatus>.Continuation] = [:]
    private var changeContinuations: [UUID: AsyncStream<Void>.Continuation] = [:]
    private var pumps: [Task<Void, Never>] = []
    public private(set) var status: SyncStatus = .idle(lastSync: nil)
    /// The current coordinator's `syncsWithServer`, readable outside the actor.
    private nonisolated let withServer: Mutex<Bool>

    public init(current: any RoutableSync) {
        self.current = current
        withServer = Mutex(current.syncsWithServer)
        Task { await self.pump() }
    }

    /// The coordinator rounds go to now.
    public var coordinator: any RoutableSync { current }

    /// Whether the current coordinator talks to a server (an unsigned build's iCloud coordinator
    /// does not: pairing then seals this device's full local view, ruling A10).
    public nonisolated var syncsWithServer: Bool { withServer.withLock { $0 } }

    /// Hand over to `next`: waits for the round in progress on the old coordinator, takes the
    /// session from it and gives it to `next`, then runs a round there.
    public func switchTo(_ next: any RoutableSync) async {
        let old = current
        await old.syncNow()
        await old.sessionLocked()
        current = next
        withServer.withLock { $0 = next.syncsWithServer }
        if let session { await next.sessionUnlocked(session) }
        pump()
        await next.syncNow()
    }

    public func statusUpdates() -> AsyncStream<SyncStatus> {
        let (stream, continuation) = AsyncStream<SyncStatus>.makeStream()
        let id = UUID()
        statusContinuations[id] = continuation
        continuation.onTermination = { [weak self] _ in Task { await self?.dropStatus(id) } }
        continuation.yield(status)
        return stream
    }

    public func remoteChanges() -> AsyncStream<Void> {
        let (stream, continuation) = AsyncStream<Void>.makeStream()
        let id = UUID()
        changeContinuations[id] = continuation
        continuation.onTermination = { [weak self] _ in Task { await self?.dropChange(id) } }
        return stream
    }

    // MARK: - SyncTrigger

    public func localChangesWritten() async { await current.localChangesWritten() }

    public func sessionUnlocked(_ session: Session) async {
        self.session = session
        await current.sessionUnlocked(session)
    }

    public func sessionLocked() async {
        session = nil
        await current.sessionLocked()
    }

    public func resetStore(with reset: @escaping @Sendable () throws -> Void) async throws {
        try await current.resetStore(with: reset)
    }

    public func safeExitIssued(_ exit: SafeExit) async { await current.safeExitIssued(exit) }

    public func syncNow() async { await current.syncNow() }

    // MARK: - Streams

    /// Follow the current coordinator's streams; a switch stops following the old one.
    private func pump() {
        for p in pumps { p.cancel() }
        generation += 1
        let (source, gen) = (current, generation)
        pumps = [
            Task { [weak self] in
                for await s in await source.statusUpdates() {
                    guard !Task.isCancelled else { return }
                    await self?.forward(status: s, generation: gen)
                }
            },
            Task { [weak self] in
                for await _ in await source.remoteChanges() {
                    guard !Task.isCancelled else { return }
                    await self?.forwardChange(generation: gen)
                }
            },
        ]
    }

    private func forward(status new: SyncStatus, generation gen: Int) {
        guard gen == generation else { return }
        status = new
        for c in statusContinuations.values { c.yield(new) }
    }

    private func forwardChange(generation gen: Int) {
        guard gen == generation else { return }
        for c in changeContinuations.values { c.yield(()) }
    }

    private func dropStatus(_ id: UUID) { statusContinuations[id] = nil }
    private func dropChange(_ id: UUID) { changeContinuations[id] = nil }
}
