import AuthenticationServices
import Foundation
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
