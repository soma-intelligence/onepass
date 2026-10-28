import Foundation
import Synchronization
import Testing

@testable import VaultKit

/// A sync layer whose store reset fails while `failing` is set (a store held open elsewhere).
final class FailingResetSync: SyncTrigger {
    private let failing = Mutex(true)
    func heal() { failing.withLock { $0 = false } }

    func localChangesWritten() async {}
    func sessionUnlocked(_ session: Session) async {}
    func sessionLocked() async {}
    func resetStore(with reset: @escaping @Sendable () throws -> Void) async throws {
        if failing.withLock({ $0 }) { throw VaultError.other("magasin occupé") }
        try await CoreThread.run(reset)
    }
}

@MainActor
@Suite("Revoked device erase")
struct RevokedEraseTests {
    init() { VaultKitStrings.pinSourceLanguage() }

    /// The erase of a revoked device failed: the session says so (never "effacées"), keeps the
    /// revoked state across a relaunch, and erases at the next refresh (L6).
    @Test func failedEraseIsReportedAndRetried() async throws {
        let f = try await PairingFixture(server: true)
        defer { f.cleanUp() }
        try await f.pairFull()
        f.newcomer.lock()
        try await f.approver.refreshDevices()
        let other = try #require(f.approver.devices.first { !$0.isThisDevice })
        try await f.approver.revokeDevice(other.id, password: testPassword)
        try await #require(f.server).deliver(to: f.newcomerPath)

        let sync = FailingResetSync()
        var environment = f.newcomerHarness.environment
        environment.sync = sync
        let revoked = VaultSession(environment: environment)
        await #expect(throws: VaultError.deviceRevoked) { try await revoked.unlock(password: testPassword) }
        #expect(revoked.state == .failed(.deviceRevoked))
        #expect(revoked.revokedEraseFailed)
        #expect(try storeState(dbPath: f.newcomerPath) == .account)

        // Next launch: still the revoked screen, not the lock screen of a revoked account.
        let relaunched = VaultSession(environment: environment)
        #expect(relaunched.state == .failed(.deviceRevoked))
        #expect(relaunched.revokedEraseFailed)
        await relaunched.refresh()
        #expect(relaunched.state == .failed(.deviceRevoked), "the reset still fails")

        sync.heal()
        await relaunched.refresh()
        #expect(!relaunched.revokedEraseFailed)
        #expect(try storeState(dbPath: f.newcomerPath) == .empty)
        #expect(f.newcomerHarness.settings.accountID == nil)
        #expect(relaunched.state == .noAccount)
    }
}
