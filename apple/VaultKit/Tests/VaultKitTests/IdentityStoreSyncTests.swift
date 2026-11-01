import AuthenticationServices
import Foundation
import Synchronization
import Testing

@testable import VaultKit

func identity(
    _ kind: FfiAutofillKind = .password, service: String = "exemple.fr", user: String = "camille@exemple.fr",
    record: String = "aa:bb", favorite: Bool = false, rank: UInt32 = 0, credential: Data = Data(),
    handle: Data = Data()
) -> FfiAutofillIdentity {
    FfiAutofillIdentity(
        kind: kind, service: service, user: user, recordId: record, favorite: favorite, rank: rank,
        credentialId: credential, userHandle: handle)
}

@Suite("Identity store sync")
struct IdentityStoreSyncTests {
    @Test func debounceCoalesces() async throws {
        let store = InMemoryIdentityStore()
        let sync = IdentityStoreSync(client: store, debounce: .milliseconds(300))
        for i in 0..<5 {
            await sync.schedule { [identity(user: "u\(i)")] }
            try await Task.sleep(for: .milliseconds(20))
        }
        await sync.waitForIdle()
        #expect(store.replaceCount == 1)
        #expect(store.identities.map(\.user) == ["u4"])
    }

    @Test func takePendingTellsWhetherARefreshWaits() async throws {
        let store = InMemoryIdentityStore()
        let sync = IdentityStoreSync(client: store, debounce: .seconds(600))
        #expect(await !sync.takePending())
        await sync.schedule { [identity()] }
        #expect(await sync.takePending())
        // Taken: dropped, and nothing waits any more.
        #expect(await !sync.takePending())
        await sync.waitForIdle()
        #expect(store.replaceCount == 0)

        // Once its identities are read, a refresh no longer waits.
        let quick = IdentityStoreSync(client: store, debounce: .milliseconds(10))
        await quick.schedule { [identity(user: "lu")] }
        await quick.waitForIdle()
        #expect(store.identities.map(\.user) == ["lu"])
        #expect(await !quick.takePending())
    }

    /// A lock landing after a refresh read its identities but before it replaced the store: the
    /// refresh still publishes (the lock found nothing waiting, so it publishes nothing itself).
    @Test func refreshAlreadyReadStillPublishesAcrossTakePending() async {
        let store = InMemoryIdentityStore()
        let sync = IdentityStoreSync(client: store, debounce: .milliseconds(10))
        let taken = Mutex<Bool?>(nil)
        await sync.setAfterReadHook {
            let due = await sync.takePending()
            taken.withLock { $0 = due }
        }
        await sync.schedule { [identity(user: "lu")] }
        await sync.waitForIdle()
        #expect(taken.withLock { $0 } == false)
        #expect(store.identities.map(\.user) == ["lu"])
    }

    /// `replaceSoon` returns before the store call ends, and a `clear` sent after it runs after it.
    @Test func replaceSoonKeepsItsPlaceBeforeAClear() async {
        let store = GatedIdentityStore()
        let sync = IdentityStoreSync(client: store, debounce: .seconds(600))
        await sync.replaceSoon([identity()])
        #expect(store.inner.identities.isEmpty)
        let cleared = Task { await sync.clear() }
        store.open()
        await cleared.value
        #expect(store.inner.replaceCount == 1)
        #expect(store.inner.removeCount == 1)
        #expect(store.inner.identities.isEmpty)
    }

    @Test func disabledStoreIsLeftAlone() async {
        let store = InMemoryIdentityStore(enabled: false)
        let sync = IdentityStoreSync(client: store, debounce: .milliseconds(10))
        await sync.schedule { [identity()] }
        await sync.waitForIdle()
        #expect(store.replaceCount == 0)
        #expect(store.identities.isEmpty)
    }

    @Test func clearCancelsPendingAndEmpties() async {
        let store = InMemoryIdentityStore()
        let sync = IdentityStoreSync(client: store, debounce: .milliseconds(10))
        await sync.schedule { [identity()] }
        await sync.waitForIdle()
        #expect(store.identities.count == 1)

        let slow = IdentityStoreSync(client: store, debounce: .seconds(5))
        await slow.schedule { [identity(user: "trop tard")] }
        await slow.clear()
        await slow.waitForIdle()
        #expect(store.identities.isEmpty)
        #expect(store.removeCount == 1)
        #expect(store.replaceCount == 1)
    }

    @Test func failingProviderKeepsStore() async {
        struct Boom: Error {}
        let store = InMemoryIdentityStore()
        let sync = IdentityStoreSync(client: store, debounce: .milliseconds(10))
        await sync.schedule { [identity()] }
        await sync.waitForIdle()
        await sync.schedule { throw Boom() }
        await sync.waitForIdle()
        #expect(store.identities.count == 1)
        #expect(store.replaceCount == 1)
    }

    @Test func builderMapsKindsAndRank() throws {
        let built = AutoFillIdentityBuilder.credentialIdentities([
            identity(.password, service: "exemple.fr", user: "camille", record: "v:1", favorite: true, rank: 50),
            identity(.oneTimeCode, service: "exemple.fr", user: "camille", record: "v:1"),
            identity(
                .passkey, service: "example.com", user: "camille", record: "v:2",
                credential: Data([1, 2, 3]), handle: Data([4, 5])),
        ])
        #expect(built.count == 3)

        let password = try #require(built[0] as? ASPasswordCredentialIdentity)
        #expect(password.serviceIdentifier.identifier == "exemple.fr")
        #expect(password.serviceIdentifier.type == .domain)
        #expect(password.user == "camille")
        #expect(password.recordIdentifier == "v:1")
        #expect(password.rank == 50)

        let code = try #require(built[1] as? ASOneTimeCodeCredentialIdentity)
        #expect(code.serviceIdentifier.identifier == "exemple.fr")
        #expect(code.serviceIdentifier.type == .domain)
        #expect(code.label == "camille")
        #expect(code.recordIdentifier == "v:1")
        #expect(code.rank == 0)

        let passkey = try #require(built[2] as? ASPasskeyCredentialIdentity)
        #expect(passkey.relyingPartyIdentifier == "example.com")
        #expect(passkey.userName == "camille")
        #expect(passkey.credentialID == Data([1, 2, 3]))
        #expect(passkey.userHandle == Data([4, 5]))
        #expect(passkey.recordIdentifier == "v:2")
    }

    @Test func notifierDeliversPosts() async throws {
        let notifier = StoreChangeNotifier(name: "me.somalabs.onepass.tests.\(UUID().uuidString)")
        let stream = notifier.changes()
        let received = Task {
            for await _ in stream { return true }
            return false
        }
        notifier.post()
        let got = try await withTimeout(.seconds(5)) { await received.value }
        #expect(got)
    }
}

/// Runs `work`, failing the test when it takes longer than `limit`.
func withTimeout<T: Sendable>(
    _ limit: Duration, _ work: @escaping @Sendable () async -> T
) async throws -> T {
    try await withThrowingTaskGroup(of: T?.self) { group in
        group.addTask { await work() }
        group.addTask {
            try await Task.sleep(for: limit)
            return nil
        }
        defer { group.cancelAll() }
        guard let first = try await group.next(), let value = first else {
            throw TimeoutError()
        }
        return value
    }
}

struct TimeoutError: Error {}

/// An in-memory store whose replacements wait until `open()` (a slow `ASCredentialIdentityStore` XPC call).
final class GatedIdentityStore: IdentityStoreClient {
    let inner = InMemoryIdentityStore()
    private let gate = Mutex(false)
    /// A replacement started (it may still be waiting for the gate).
    private let started = Mutex(0)

    var replacementsStarted: Int { started.withLock { $0 } }
    func open() { gate.withLock { $0 = true } }

    func isEnabled() async -> Bool { true }

    func replaceAll(_ identities: [FfiAutofillIdentity]) async throws {
        started.withLock { $0 += 1 }
        while !gate.withLock({ $0 }) { try? await Task.sleep(for: .milliseconds(5)) }
        try await inner.replaceAll(identities)
    }

    func removeAll() async throws { try await inner.removeAll() }
}
