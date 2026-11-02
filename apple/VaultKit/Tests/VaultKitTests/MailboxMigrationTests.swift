import Foundation
import Testing
@testable import VaultKit

/// X1b Task 8: an iCloud account moves to a mailbox (cross-platform spec D.5, steps 1 to 3).
@Suite("Mailbox migration")
struct MailboxMigrationTests {
    static let hosted = URL(string: "https://mailbox.somalabs.me/functions/v1/mailbox")!

    final class Fixture: @unchecked Sendable {
        let dir: URL
        let store: SyncStoreHandle
        let session: Session
        let secretKey: SecretBytes
        let keychain = InMemoryKeychain()
        let provisioning = FakeMailboxProvisioning()
        let remote = InMemoryRemote()
        let cloudKit: SyncCoordinator
        let router: SyncRouter

        init() throws {
            dir = FileManager.default.temporaryDirectory.appendingPathComponent("onepass-migration-\(UUID().uuidString)")
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            let db = dir.appendingPathComponent("v.db").path
            let created = try createAccountWithKdf(
                dbPath: db, password: "Lanterne vive 77 sur le quai !", kdf: FfiKdfParams(mKib: 8192, t: 1, p: 1))
            session = created.session
            secretKey = SecretBytes(copying: Data(created.secretKey.utf8))
            store = try openSyncStore(dbPath: db)
            cloudKit = SyncCoordinator(store: store, remote: remote)
            router = SyncRouter(current: cloudKit)
        }

        var credentials: MailboxCredentialStore { MailboxCredentialStore(keychain: keychain) }

        func migration() -> MailboxMigration {
            let setup = MailboxSetup(provisioning: provisioning, credentials: credentials, store: store, hosted: MailboxMigrationTests.hosted)
            let parts = MailboxMigration.Parts(
                setup: setup, provisioning: provisioning, credentials: credentials, remote: remote,
                cloudKit: cloudKit, router: router,
                makeCoordinator: { sync, _ in MailboxSyncCoordinator(sync: sync, serverName: "test") })
            return MailboxMigration(store: store, parts: parts)
        }

        deinit { try? FileManager.default.removeItem(at: dir) }
    }

    @Test(arguments: [
        (SyncStatus.idle(lastSync: Date()), false, MailboxMigration.Blocker.locked),
        (SyncStatus.offline, true, .offline),
        (SyncStatus.refused(kind: "x"), true, .refused),
        (SyncStatus.idle(lastSync: nil), true, .notSynced),
        (SyncStatus.error("x"), true, .notSynced),
    ])
    func preconditionsRefused(status: SyncStatus, unlocked: Bool, blocker: MailboxMigration.Blocker) async throws {
        let f = try Fixture()
        let blocked = await f.migration().preflight(session: unlocked ? f.session : nil, status: status)
        #expect(blocked == blocker)
        #expect(await f.migration().preflight(session: f.session, status: .idle(lastSync: Date())) == nil)
    }

    @Test func claimBeforeAdopt() async throws {
        let f = try Fixture()
        let m = f.migration()
        let session = f.session
        await m.setBeforeClaim {
            // The claim is about to be sent: nothing adopted yet.
            #expect((try? session.syncHome()) == nil)
        }
        let outcome = await m.start(choice: .hosted, session: f.session, secretKey: f.secretKey)
        guard case .done(let home) = outcome else { Issue.record("\(outcome)"); return }
        #expect(try f.session.syncHome()?.backend == home.backend)
        // The claim is in iCloud, under the account's SyncHome record.
        let id = try f.session.syncHomeRecordId()
        let batches = await f.remote.sentBatches
        #expect(batches.contains([RecordName(kind: CloudKitMapping.syncHomeKind, id: id)]))
        #expect(try await SyncBackendState.read(store: f.store) == .mailbox(home))
    }

    @Test func cutAfterCreateResumes() async throws {
        let f = try Fixture()
        let first = f.migration()
        await first.setInterruptAfter { if case .mailboxReady = $0 { true } else { false } }
        #expect(await first.start(choice: .hosted, session: f.session, secretKey: f.secretKey) == .failed("interrupted"))
        let outcome = await f.migration().start(choice: .hosted, session: f.session, secretKey: f.secretKey)
        guard case .done = outcome else { Issue.record("\(outcome)"); return }
        #expect(f.provisioning.mailboxesCreated == 1)
    }

    @Test func cutAfterClaimResumesUpload() async throws {
        let f = try Fixture()
        let first = f.migration()
        await first.setInterruptAfter { if case .claimed = $0 { true } else { false } }
        #expect(await first.start(choice: .hosted, session: f.session, secretKey: f.secretKey) == .failed("interrupted"))
        // The claim won but nothing is adopted yet: the launch resumes from the claim.
        #expect(try f.session.syncHome() == nil)
        let resumed = await f.migration().resume(session: f.session)
        guard case .done(let home) = resumed else { Issue.record("\(String(describing: resumed))"); return }
        #expect(f.provisioning.mailboxesCreated == 1)
        #expect(try f.session.syncHome()?.backend == home.backend)
        #expect(await f.cloudKit.isStoppedForMigration)
        #expect(await f.migration().resume(session: f.session) == nil)
    }

    @Test func lostRaceAbandonsAndFollows() async throws {
        let f = try Fixture()
        let winner = MailboxHome(baseURL: Self.hosted, mailboxID: String(repeating: "f", count: 32))
        let session = f.session
        let remote = f.remote
        let m = f.migration()
        await m.setBeforeClaim {
            // Another device of the account claims first.
            guard let signed = try? session.signSyncHome(backend: winner.backend),
                  let id = try? session.syncHomeRecordId()
            else { return }
            _ = try? await remote.send([RemoteRecord(
                name: RecordName(kind: CloudKitMapping.syncHomeKind, id: id), version: 1, data: signed, serverMeta: nil)])
        }
        let outcome = await m.start(choice: .hosted, session: f.session, secretKey: f.secretKey)
        #expect(outcome == .lostRace(winner: winner))
        #expect(f.provisioning.sync.calls.contains("abandon"))
        #expect(f.keychain.keys.isEmpty)
        // The winner's home is the account's: no fork, this device follows it.
        #expect(try f.session.syncHome()?.backend == winner.backend)
        #expect(await f.migration().state() == .idle)
        #expect(!(await f.cloudKit.isStoppedForMigration))
    }

    @Test func cloudKitCoordinatorStoppedBeforeReset() async throws {
        let f = try Fixture()
        let outcome = await f.migration().start(choice: .hosted, session: f.session, secretKey: f.secretKey)
        guard case .done = outcome else { Issue.record("\(outcome)"); return }
        #expect(await f.cloudKit.isStoppedForMigration)
        let sent = await f.remote.sentBatches.count
        await f.cloudKit.localChangesWritten()
        await f.cloudKit.syncNow()
        #expect(await f.remote.sentBatches.count == sent)
        // The router now rounds on the mailbox.
        await f.router.syncNow()
        #expect(f.provisioning.sync.rounds >= 1)
    }
}
