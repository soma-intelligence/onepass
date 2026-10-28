import Foundation
import Testing

@testable import VaultKit

/// The new device after the security review of milestone 2b: a hostile neighbour on the local
/// network cannot hold or kill the pairing service (M2), and a received account does not wait
/// forever for its master password nor take unlimited guesses (M3).
@MainActor
@Suite("Pairing new device hardening")
struct PairingNewcomerHardeningTests {
    init() { VaultKitStrings.pinSourceLanguage() }

    private func showing(_ n: PairingNewcomerFlow) async -> String? {
        var qr: String?
        _ = await eventually {
            if case .showingCode(let text, _) = n.state { qr = text }
            return qr != nil
        }
        return qr
    }

    /// A first connection that never answers does not take the service away: the approver who
    /// scanned the QR still gets the code (M2).
    @Test(.timeLimit(.minutes(2))) func silentFirstConnectionDoesNotBlockApprover() async throws {
        let f = try await PairingFixture(server: true)
        defer { f.cleanUp() }
        let n = PairingNewcomerFlow(
            vault: f.newcomer, mode: .personal, listener: f.network, deviceName: "iPad", deviceKind: .tablet,
            renewEvery: .seconds(600))
        n.start()
        defer { n.cancel() }
        let qr = try #require(await showing(n))
        let service = try pairingServiceName(qrText: qr)
        let squatter = try await f.network.connect(serviceName: service)
        defer { squatter.close() }
        // The squatter got the Hello, and says nothing.
        _ = try await squatter.receive()

        let a = PairingApproverFlow(vault: f.approver, connector: f.network)
        let begin = Task { await a.begin(qrText: qr) }
        #expect(await eventually {
            if case .comparing = a.state { true } else { false }
        })
        begin.cancel()
        #expect(await eventually {
            if case .comparing = n.state { true } else { false }
        })
        // The winner took the session: the squatter is closed.
        await #expect(throws: PairingTransportError.closed) { _ = try await squatter.receive() }
    }

    /// A key exchange above 16 KiB closes that connection without reading it, and a malformed one
    /// only renews the code: the pairing goes on (M2).
    @Test(.timeLimit(.minutes(2))) func hostileKeyExchangesOnlyRenewTheCode() async throws {
        let f = try await PairingFixture(server: true)
        defer { f.cleanUp() }
        let n = PairingNewcomerFlow(
            vault: f.newcomer, mode: .personal, listener: f.network, deviceName: "iPad", deviceKind: .tablet,
            renewEvery: .seconds(600))
        n.start()
        defer { n.cancel() }
        let qr = try #require(await showing(n))
        let service = try pairingServiceName(qrText: qr)

        let big = try await f.network.connect(serviceName: service)
        _ = try await big.receive()
        try await big.send(Data(count: PairingFrame.maxHandshakeBytes + 1))
        await #expect(throws: PairingTransportError.closed) { _ = try await big.receive() }
        // Refused before the core saw it: the same code stays.
        if case .showingCode(let text, _) = n.state { #expect(text == qr) } else { Issue.record("\(n.state)") }

        let garbage = try await f.network.connect(serviceName: service)
        _ = try await garbage.receive()
        try await garbage.send(Data("OPK1 pas une enveloppe".utf8))
        await #expect(throws: PairingTransportError.closed) { _ = try await garbage.receive() }
        // A new code replaced the spent one; nothing failed.
        var renewed: String?
        #expect(await eventually {
            if case .showingCode(let text, _) = n.state, text != qr { renewed = text }
            return renewed != nil
        })
        let a = PairingApproverFlow(vault: f.approver, connector: f.network)
        await a.begin(qrText: try #require(renewed))
        guard case .comparing(let sas, _, _) = a.state else {
            Issue.record("approver not comparing: \(a.state)")
            return
        }
        #expect(await eventually { n.state == .comparing(sas: sas) })
    }

    /// A connection that never sends its key exchange is closed at the handshake deadline (M2).
    @Test(.timeLimit(.minutes(1))) func silentConnectionClosedAtDeadline() async throws {
        let f = try await PairingFixture(server: false)
        defer { f.cleanUp() }
        let n = PairingNewcomerFlow(
            vault: f.newcomer, mode: .personal, listener: f.network, deviceName: "iPad", deviceKind: .tablet,
            renewEvery: .seconds(600), handshakeTimeout: .milliseconds(300))
        n.start()
        defer { n.cancel() }
        let qr = try #require(await showing(n))
        let squatter = try await f.network.connect(serviceName: try pairingServiceName(qrText: qr))
        _ = try await squatter.receive()
        await #expect(throws: PairingTransportError.closed) { _ = try await squatter.receive() }
        if case .showingCode = n.state {} else { Issue.record("new device stopped: \(n.state)") }
    }

    /// Wrong master passwords count toward the unlock lockout, and the received account is dropped
    /// at the count where the lockout starts (M3).
    @Test func wrongPasswordsDropTheGrant() async throws {
        let f = try await PairingFixture(server: true)
        defer { f.cleanUp() }
        let n = try await f.grantFull()
        let settings = f.newcomerHarness.settings
        for attempt in 1..<PairingNewcomerFlow.maxImportAttempts {
            await n.importAndUnlock(password: "faux mot de passe")
            #expect(n.state == .receivedFull)
            #expect(n.importError == .wrongPassword)
            #expect(settings.failedUnlocks == attempt)
        }
        await n.importAndUnlock(password: "faux mot de passe")
        #expect(n.state == .failed(.tooManyAttempts))
        #expect(settings.lockoutUntil != nil)
        // The grant is gone: even the right password imports nothing.
        await n.importAndUnlock(password: testPassword)
        #expect(f.newcomer.state == .noAccount)
        #expect(try storeState(dbPath: f.newcomerPath) == .empty)
        #expect(settings.accountID == nil)
    }

    /// A lockout in force refuses the import before any password check (M3).
    @Test func lockoutRefusesImport() async throws {
        let f = try await PairingFixture(server: true)
        defer { f.cleanUp() }
        let n = try await f.grantFull()
        let until = f.newcomerHarness.clock.now.addingTimeInterval(30)
        f.newcomerHarness.settings.lockoutUntil = until
        await n.importAndUnlock(password: testPassword)
        #expect(n.importError == .lockedOut(until: until))
        #expect(n.state == .receivedFull)
        #expect(f.newcomer.state == .noAccount)
    }

    /// A received account waits a bounded time for its password, and leaving drops it (M3).
    @Test func idleOrCancelledGrantIsDropped() async throws {
        let f = try await PairingFixture(server: true)
        defer { f.cleanUp() }
        f.newcomerGrantLifetime = .milliseconds(300)
        let idle = try await f.grantFull()
        #expect(await eventually { idle.state == .failed(.grantExpired) })
        await idle.importAndUnlock(password: testPassword)
        #expect(f.newcomer.state == .noAccount)

        f.newcomerGrantLifetime = .seconds(600)
        let left = try await f.grantFull()
        left.cancel()
        #expect(left.state == .cancelled)
        await left.importAndUnlock(password: testPassword)
        #expect(f.newcomer.state == .noAccount)
        #expect(try storeState(dbPath: f.newcomerPath) == .empty)
    }
}
