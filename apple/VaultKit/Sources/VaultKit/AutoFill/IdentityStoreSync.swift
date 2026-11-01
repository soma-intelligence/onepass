import AuthenticationServices
import Foundation
import Synchronization

/// The system credential identity store, behind a protocol for tests and the demo.
public protocol IdentityStoreClient: Sendable {
    /// OnePass is turned on as an AutoFill provider (the store accepts identities).
    func isEnabled() async -> Bool
    /// Replaces the whole content of the store.
    func replaceAll(_ identities: [FfiAutofillIdentity]) async throws
    func removeAll() async throws
}

/// `ASCredentialIdentityStore.shared`: identities converted by `AutoFillIdentityBuilder`.
public struct SystemIdentityStore: IdentityStoreClient {
    public init() {}

    public func isEnabled() async -> Bool {
        await ASCredentialIdentityStore.shared.state().isEnabled
    }

    public func replaceAll(_ identities: [FfiAutofillIdentity]) async throws {
        try await ASCredentialIdentityStore.shared.replaceCredentialIdentities(
            AutoFillIdentityBuilder.credentialIdentities(identities))
    }

    public func removeAll() async throws {
        try await ASCredentialIdentityStore.shared.removeAllCredentialIdentities()
    }
}

/// Does nothing, store always disabled (existing callers, unsigned builds without the extension).
public struct NoIdentityStore: IdentityStoreClient {
    public init() {}
    public func isEnabled() async -> Bool { false }
    public func replaceAll(_ identities: [FfiAutofillIdentity]) async throws {}
    public func removeAll() async throws {}
}

/// An identity store in memory (tests, demo data). Counts its calls.
public final class InMemoryIdentityStore: IdentityStoreClient {
    private struct State {
        var enabled: Bool
        var identities: [FfiAutofillIdentity] = []
        var replaceCount = 0
        var removeCount = 0
    }
    private let state: Mutex<State>

    public init(enabled: Bool = true) {
        state = Mutex(State(enabled: enabled))
    }

    public var enabled: Bool {
        get { state.withLock { $0.enabled } }
        set { state.withLock { $0.enabled = newValue } }
    }
    public var identities: [FfiAutofillIdentity] { state.withLock { $0.identities } }
    public var replaceCount: Int { state.withLock { $0.replaceCount } }
    public var removeCount: Int { state.withLock { $0.removeCount } }

    public func isEnabled() async -> Bool { enabled }

    public func replaceAll(_ identities: [FfiAutofillIdentity]) async throws {
        state.withLock {
            $0.identities = identities
            $0.replaceCount += 1
        }
    }

    public func removeAll() async throws {
        state.withLock {
            $0.identities = []
            $0.removeCount += 1
        }
    }
}

/// Keeps the system identity store in step with the vault (spec 4, ruling A5).
///
/// `schedule` debounces: only the last request of a burst runs, `debounce` after it. Store operations
/// run one after the other, in request order, so a `clear` is never overtaken by an earlier refresh.
/// A disabled store is left alone; a failing identity provider (session locked meanwhile, store error)
/// keeps the store as it was.
public actor IdentityStoreSync {
    private let client: any IdentityStoreClient
    private let debounce: Duration
    /// Bumped by every `schedule` and `clear`: a request that is no longer the latest drops out.
    private var revision = 0
    private var pending: Task<Void, Never>?
    /// The revision of the scheduled refresh whose identities were not read yet (`takePending`).
    private var pendingRevision: Int?
    private var chain: Task<Void, Never>?
    /// Tests: runs once a refresh has read its identities, before it replaces the store.
    private var afterRead: (@Sendable () async -> Void)?
    /// Refresh requests made and settled (read, dropped or superseded), readable without the
    /// actor: a lock decides at once whether a refresh may still wait (`mayHavePending`).
    private let marks = Mutex(Marks())
    /// The request mark of the latest scheduled refresh.
    private var pendingMark = 0

    private struct Marks {
        var requested = 0
        var settled = 0
    }

    public init(client: any IdentityStoreClient, debounce: Duration = .seconds(1)) {
        self.client = client
        self.debounce = debounce
    }

    /// Counts a refresh request before it reaches `schedule` (the caller queues it): until that
    /// refresh is read or dropped, `mayHavePending` is true. Returns the mark to pass to `schedule`.
    public nonisolated func noteRequest() -> Int {
        marks.withLock {
            $0.requested += 1
            return $0.requested
        }
    }

    /// A refresh was requested and not read or dropped yet (it may still be on its way to
    /// `schedule`). False means a lock has nothing to publish.
    public nonisolated var mayHavePending: Bool {
        marks.withLock { $0.requested > $0.settled }
    }

    /// Replaces the store with `identities()` after the debounce delay, unless a later `schedule` or a
    /// `clear` comes first. `mark` comes from `noteRequest` (a new one when nil).
    public func schedule(
        mark: Int? = nil, _ identities: @Sendable @escaping () async throws -> [FfiAutofillIdentity]
    ) {
        revision &+= 1
        let current = revision
        pendingRevision = current
        pendingMark = max(pendingMark, mark ?? noteRequest())
        pending?.cancel()
        let delay = debounce
        pending = Task {
            do {
                try await Task.sleep(for: delay)
            } catch {
                return
            }
            await self.enqueueReplace(revision: current, identities)
        }
    }

    /// Replaces the store with `identities` without the debounce (a pending debounced refresh is
    /// dropped), and returns once done. A disabled store is left alone; errors are ignored.
    public func replaceNow(_ identities: [FfiAutofillIdentity]) async {
        replaceSoon(identities)
        await chain?.value
    }

    /// `replaceNow` without waiting for the store (an XPC call): queued in order, so a later `clear`
    /// still runs after it.
    public func replaceSoon(_ identities: [FfiAutofillIdentity]) {
        revision &+= 1
        pending?.cancel()
        pending = nil
        settlePending()
        let current = revision
        let client = client
        enqueue {
            guard await self.isCurrent(current), await client.isEnabled() else { return }
            try? await client.replaceAll(identities)
        }
    }

    /// Cancels any pending refresh and empties the store (setting turned off, account reset). The store
    /// is emptied even when disabled (errors ignored): nothing must stay behind.
    public func clear() async {
        revision &+= 1
        pending?.cancel()
        pending = nil
        settlePending()
        let client = client
        enqueue { try? await client.removeAll() }
        await chain?.value
    }

    /// Drops the pending debounced refresh, if any (session locked: it could only fail). Queued
    /// store operations still run, a replacement queued by an earlier lock included: with nothing
    /// pending, nothing is bumped.
    public func dropPending() {
        _ = takePending()
    }

    /// Drops the pending debounced refresh like `dropPending`, and tells whether one was waiting
    /// with its identities still unread: the caller (a lock) then publishes its own reading. A
    /// refresh that already read its identities is left alone (nothing bumped): it publishes them.
    public func takePending() -> Bool {
        guard pendingRevision != nil else { return false }
        revision &+= 1
        pending?.cancel()
        pending = nil
        settlePending()
        return true
    }

    /// Tests: `hook` runs once a refresh has read its identities, before it replaces the store.
    func setAfterReadHook(_ hook: (@Sendable () async -> Void)?) {
        afterRead = hook
    }

    /// Tests: waits until the pending refresh (if any) and every queued store operation are done.
    func waitForIdle() async {
        await pending?.value
        await chain?.value
    }

    private func enqueueReplace(
        revision expected: Int, _ identities: @Sendable @escaping () async throws -> [FfiAutofillIdentity]
    ) {
        guard expected == revision else { return }
        let client = client
        enqueue {
            guard await self.isCurrent(expected), await client.isEnabled() else { return }
            guard let list = try? await identities() else { return }
            // Still the latest request once read: from here on it publishes (a lock's
            // `takePending` sees nothing waiting). A later `clear` is queued after it.
            guard await self.claim(expected) else { return }
            await self.afterRead?()
            try? await client.replaceAll(list)
        }
    }

    private func isCurrent(_ expected: Int) -> Bool { expected == revision }

    /// The refresh `expected` read its identities and is still the latest: no longer pending.
    private func claim(_ expected: Int) -> Bool {
        guard expected == revision else { return false }
        if pendingRevision == expected { settlePending() }
        return true
    }

    /// The scheduled refresh is read or dropped: no request up to its mark waits any more.
    private func settlePending() {
        pendingRevision = nil
        let mark = pendingMark
        marks.withLock { $0.settled = max($0.settled, mark) }
    }

    private func enqueue(_ op: @Sendable @escaping () async -> Void) {
        let previous = chain
        chain = Task {
            await previous?.value
            await op()
        }
    }
}
