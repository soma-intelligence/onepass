import Foundation
import Synchronization
import Testing

@testable import VaultKit

/// A sync layer with a server: `syncNow` pushes every pending row of the store, the server accepting
/// them all (it keeps what it accepted, for `deliver(to:)`).
final class PushingSync: SyncTrigger {
    let dbPath: String
    private let accepted = Mutex<[FfiRecordChange]>([])

    init(dbPath: String) { self.dbPath = dbPath }

    var syncsWithServer: Bool { true }
    func syncNow() async { _ = try? await CoreThread.run { try self.push() } }
    func localChangesWritten() async {}
    func sessionUnlocked(_ session: Session) async {}
    func sessionLocked() async {}

    @discardableResult
    func push() throws -> [FfiRecordChange] {
        let handle = try openSyncStore(dbPath: dbPath)
        let changes = try handle.pendingChanges()
        for c in changes {
            try handle.markPushed(kind: c.kind, id: c.id, version: c.version, serverMeta: Data("tag".utf8))
        }
        accepted.withLock { $0.append(contentsOf: changes) }
        return changes
    }

    /// Pushes, then fetches every row the server accepted so far into the store at `path` (on the
    /// core thread: the store checks signatures).
    func deliver(to path: String) async throws {
        try await CoreThread.run { try self.deliverNow(to: path) }
    }

    private func deliverNow(to path: String) throws {
        try push()
        let handle = try openSyncStore(dbPath: path)
        for c in accepted.withLock({ $0 }) {
            try handle.stageRemote(
                record: FfiRemoteRecord(
                    kind: c.kind, id: c.id, version: c.version, data: c.data, serverMeta: Data("tag".utf8)))
        }
        _ = try handle.commitRemote()
    }
}

/// Two devices: an approver with an account and one login, and an empty new device.
@MainActor
final class PairingFixture {
    let approverHarness: SessionHarness
    let newcomerHarness: SessionHarness
    let approver: VaultSession
    let newcomer: VaultSession
    let network = InMemoryPairingNetwork()
    let server: PushingSync?
    var login: FfiItem!
    /// How long the approver waits for the new device's confirmation after presence (L5).
    var approverPeerTimeout: Duration = PairingApproverFlow.peerTimeout
    /// How long the new device keeps a received account without an attempt (M3).
    var newcomerGrantLifetime: Duration = PairingNewcomerFlow.grantLifetime

    static let newcomerName = "iPad de Camille"

    init(server withServer: Bool) async throws {
        approverHarness = try SessionHarness()
        newcomerHarness = try SessionHarness()
        var environment = approverHarness.environment
        let server = withServer ? PushingSync(dbPath: environment.databaseURL.path) : nil
        if let server { environment.sync = server }
        self.server = server
        approver = VaultSession(environment: environment)
        newcomer = newcomerHarness.makeSession()
        _ = try await approver.createAccount(password: testPassword, displayName: "Camille", mode: .personal)
        login = try await addItem(approver, title: "Messagerie exemple.fr", type: .login)
    }

    var newcomerPath: String { newcomerHarness.environment.databaseURL.path }

    func cleanUp() {
        approverHarness.cleanUp()
        newcomerHarness.cleanUp()
    }

    /// Both flows up to the code comparison, codes checked equal.
    func compare(mode: FfiDeviceMode) async throws -> (PairingNewcomerFlow, PairingApproverFlow, String) {
        let n = PairingNewcomerFlow(
            vault: newcomer, mode: mode, listener: network, deviceName: Self.newcomerName, deviceKind: .tablet,
            grantLifetime: newcomerGrantLifetime)
        n.start()
        var qr: String?
        #expect(await eventually {
            if case .showingCode(let text, _) = n.state { qr = text }
            return qr != nil
        })
        let qrText = try #require(qr)
        #expect(qrText.hasPrefix("OPPAIR1:"))
        let service = try pairingServiceName(qrText: qrText)
        let a = PairingApproverFlow(vault: approver, connector: network, peerTimeout: approverPeerTimeout)
        await a.begin(qrText: qrText)
        guard case .comparing(let sas, let peer, let requested) = a.state else {
            Issue.record("approver not comparing: \(a.state)")
            throw CancellationError()
        }
        #expect(peer.name == Self.newcomerName)
        #expect(peer.kind == .tablet)
        #expect(requested == mode)
        #expect(await eventually { n.state == .comparing(sas: sas) })
        return (n, a, service)
    }

    /// A full pairing, up to the newcomer holding the grant.
    func grantFull(mode: FfiDeviceMode = .personal) async throws -> PairingNewcomerFlow {
        let (n, a, _) = try await compare(mode: mode)
        await n.confirmCode()
        #expect(n.state == .waitingForApproval)
        await a.approve(mode: mode, password: testPassword)
        #expect(a.approvalError == nil)
        #expect(await eventually { n.state == .receivedFull })
        #expect(await eventually { a.state == .done })
        return n
    }

    /// Pairs and unlocks the new device.
    func pairFull() async throws {
        let n = try await grantFull()
        await n.importAndUnlock(password: testPassword)
        #expect(n.state == .done)
        #expect(newcomer.state == .unlocked)
    }
}

@MainActor
@Suite("Pairing")
struct PairingFlowTests {
    init() { VaultKitStrings.pinSourceLanguage() }

    @Test func fullPairingOverInMemoryTransport() async throws {
        let f = try await PairingFixture(server: true)
        defer { f.cleanUp() }
        try await f.approver.refreshDevices()
        #expect(f.approver.devices.count == 1, "the account registered its first device")
        #expect(f.approver.devices.first?.isThisDevice == true)

        let n = try await f.grantFull()
        // A wrong password keeps the grant: nothing stays in the store, no Secret Key yet.
        await n.importAndUnlock(password: "faux mot de passe")
        #expect(n.state == .receivedFull)
        #expect(n.importError == .wrongPassword)
        #expect(try storeState(dbPath: f.newcomerPath) == .empty)
        #expect(f.newcomerHarness.settings.accountID == nil)

        await n.importAndUnlock(password: testPassword)
        #expect(n.state == .done)
        #expect(f.newcomer.state == .unlocked)
        #expect(f.newcomer.summaries.map(\.title) == ["Messagerie exemple.fr"])
        let accountID = try #require(f.approverHarness.settings.accountID)
        #expect(f.newcomerHarness.settings.accountID == accountID)
        let stored = try SecretKeyVault(keychain: f.newcomerHarness.keychain).load(accountID: accountID)
        let original = try SecretKeyVault(keychain: f.approverHarness.keychain).load(accountID: accountID)
        #expect(stored != nil && stored == original)

        // The approver listed the new device and pushed the list.
        #expect(f.approver.devices.count == 2)
        let added = try #require(f.approver.devices.first { !$0.isThisDevice })
        #expect(added.name == PairingFixture.newcomerName)
        #expect(added.addedBy == f.approver.thisDeviceID)
        let approverPath = f.approverHarness.environment.databaseURL.path
        #expect(try await CoreThread.run { try openSyncStore(dbPath: approverPath).pendingChanges() }.isEmpty)

        // The new device locks and opens again with the same password and the stored Secret Key.
        f.newcomer.lock()
        try await f.newcomer.unlock(password: testPassword)
        try await f.newcomer.refreshDevices()
        #expect(f.newcomer.thisDeviceID == added.id)
    }

    @Test func fullPairingWithoutSyncIncludesLocalState() async throws {
        let f = try await PairingFixture(server: false)
        defer { f.cleanUp() }
        try await f.pairFull()
        #expect(f.newcomer.summaries.map(\.title) == ["Messagerie exemple.fr"])
        try await f.newcomer.refreshDevices()
        #expect(f.newcomer.devices.count == 2)
        #expect(f.newcomer.devices.contains { $0.isThisDevice && $0.name == PairingFixture.newcomerName })
    }

    @Test func codeRejectedSendsNothing() async throws {
        let f = try await PairingFixture(server: true)
        defer { f.cleanUp() }
        let (n, a, service) = try await f.compare(mode: .personal)
        n.rejectCode()
        #expect(n.state == .failed(.codeRejected))
        #expect(PairingFailure.codeRejected.message == "Appairage annulé. Rien n'a été envoyé.")
        // Only the Hello left the new device; the approver sent only its key exchange.
        #expect(f.network.frames(service: service, from: .listener).count == 1)
        #expect(f.network.frames(service: service, from: .connector).count == 1)
        #expect(await eventually {
            if case .failed = a.state { true } else { false }
        })
        await a.approve(mode: .personal, password: testPassword)
        #expect(f.network.frames(service: service, from: .connector).count == 1)
        try await f.approver.refreshDevices()
        #expect(f.approver.devices.count == 1)
        #expect(try storeState(dbPath: f.newcomerPath) == .empty)
    }

    /// Over the real local network transport (loopback): "Ils sont différents" on the approver ends
    /// with that reason on the approver, not with "La connexion a été coupée" from its own close.
    @Test(.timeLimit(.minutes(2))) func approverRejectKeepsItsReasonOverLocalNetwork() async throws {
        let f = try await PairingFixture(server: false)
        defer { f.cleanUp() }
        let n = PairingNewcomerFlow(
            vault: f.newcomer, mode: .personal, listener: LocalNetworkPairingListener(),
            deviceName: Self.localName, deviceKind: .tablet,
            // Under a loaded test run the approver may connect late: no renewed QR in between.
            renewEvery: .seconds(600))
        n.start()
        defer { n.cancel() }
        var qr: String?
        #expect(await eventually {
            if case .showingCode(let text, _) = n.state { qr = text }
            return qr != nil
        })
        let a = PairingApproverFlow(vault: f.approver, connector: LocalNetworkPairingConnector(timeout: .seconds(15)))
        await a.begin(qrText: try #require(qr))
        if case .failed(.notFound) = a.state {
            try Test.cancel("Bonjour unavailable here: the pairing service could not be resolved on this Mac.")
        }
        guard case .comparing = a.state else {
            Issue.record("approver not comparing: \(a.state)")
            return
        }
        a.cancel()
        // Let the receiver see its own close.
        try await Task.sleep(for: .milliseconds(300))
        #expect(a.state == .failed(.codeRejected))
        #expect(await eventually {
            if case .failed = n.state { true } else { false }
        })
    }

    static let localName = "iPad de test"

    @Test func approvalNeedsPresence() async throws {
        let f = try await PairingFixture(server: true)
        defer { f.cleanUp() }
        let (n, a, service) = try await f.compare(mode: .personal)
        await n.confirmCode()
        // No biometrics enrolled and no password: nothing is granted.
        await a.approve(mode: .personal)
        #expect(a.approvalError == .passwordRequired)
        await a.approve(mode: .personal, password: "faux")
        #expect(a.approvalError == .wrongPassword)
        #expect(f.network.frames(service: service, from: .connector).count == 1)
        await a.approve(mode: .personal, password: testPassword)
        #expect(await eventually { n.state == .receivedFull })
    }
}
