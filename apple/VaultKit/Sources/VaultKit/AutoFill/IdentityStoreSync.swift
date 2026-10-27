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
    private var chain: Task<Void, Never>?

    public init(client: any IdentityStoreClient, debounce: Duration = .seconds(1)) {
        self.client = client
        self.debounce = debounce
    }

    /// Replaces the store with `identities()` after the debounce delay, unless a later `schedule` or a
    /// `clear` comes first.
    public func schedule(_ identities: @Sendable @escaping () async throws -> [FfiAutofillIdentity]) {
        revision &+= 1
        let current = revision
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

    /// Replaces the store with `identities` without waiting (a pending debounced refresh is dropped),
    /// and returns once done. A disabled store is left alone; errors are ignored.
    public func replaceNow(_ identities: [FfiAutofillIdentity]) async {
        revision &+= 1
        pending?.cancel()
        pending = nil
        let current = revision
        let client = client
        enqueue {
            guard await self.isCurrent(current), await client.isEnabled() else { return }
            try? await client.replaceAll(identities)
        }
        await chain?.value
    }

    /// Cancels any pending refresh and empties the store (setting turned off, account reset). The store
    /// is emptied even when disabled (errors ignored): nothing must stay behind.
    public func clear() async {
        revision &+= 1
        pending?.cancel()
        pending = nil
        let client = client
        enqueue { try? await client.removeAll() }
        await chain?.value
    }

    /// Drops the pending debounced refresh, if any (session locked: it could only fail). Queued
    /// store operations still run.
    public func dropPending() {
        revision &+= 1
        pending?.cancel()
        pending = nil
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
            guard await self.isCurrent(expected) else { return }
            try? await client.replaceAll(list)
        }
    }

    private func isCurrent(_ expected: Int) -> Bool { expected == revision }

    private func enqueue(_ op: @Sendable @escaping () async -> Void) {
        let previous = chain
        chain = Task {
            await previous?.value
            await op()
        }
    }
}
