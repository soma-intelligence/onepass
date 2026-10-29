import Foundation
import Testing

@testable import VaultKit

/// The rendezvous direction (version 2): the unlocked device shows a code, the new device scans or
/// types it. Same two-device fixture as `PairingFlowTests`.
extension PairingFixture {
    /// The approver shows a code and waits.
    func host(renewEvery: Duration = PairingApproverFlow.renewInterval) async throws -> (PairingApproverFlow, FfiHostCode) {
        let a = PairingApproverFlow(
            vault: approver, listener: network, peerTimeout: approverPeerTimeout, renewEvery: renewEvery)
        a.startHosting()
        var shown: FfiHostCode?
        #expect(await eventually {
            if case .hosting(let code) = a.state { shown = code }
            return shown != nil
        })
        return (a, try #require(shown))
    }

    /// Both flows up to the code comparison, the newcomer typing `code(shown)`.
    func compareHosted(
        mode: FfiDeviceMode, typed: Bool = true
    ) async throws -> (PairingNewcomerFlow, PairingApproverFlow, String) {
        let (a, shown) = try await host()
        let n = PairingNewcomerFlow(
            vault: newcomer, mode: mode, listener: network, deviceName: Self.newcomerName, deviceKind: .tablet,
            grantLifetime: newcomerGrantLifetime)
        n.join(code: typed ? shown.shortText.lowercased() : shown.qrText, connector: network)
        #expect(await eventually {
            if case .comparing = a.state, case .comparing = n.state { true } else { false }
        })
        guard case .comparing(let sas, let peer, let requested) = a.state else {
            Issue.record("approver not comparing: \(a.state)")
            throw CancellationError()
        }
        #expect(peer.name == Self.newcomerName)
        #expect(peer.kind == .tablet)
        #expect(requested == mode)
        #expect(n.state == .comparing(sas: sas))
        return (n, a, shown.serviceName)
    }
}

@MainActor
@Suite("Pairing, rendezvous")
struct PairingRendezvousTests {
    init() { VaultKitStrings.pinSourceLanguage() }

    @Test func fullPairingWithATypedCode() async throws {
        let f = try await PairingFixture(server: true)
        defer { f.cleanUp() }
        let (n, a, _) = try await f.compareHosted(mode: .personal)
        await n.confirmCode()
        #expect(n.state == .waitingForApproval)
        await a.approve(mode: .personal, password: testPassword)
        #expect(a.approvalError == nil)
        #expect(await eventually { n.state == .receivedFull })
        #expect(await eventually { a.state == .done })

        await n.importAndUnlock(password: testPassword)
        #expect(n.state == .done)
        #expect(f.newcomer.state == .unlocked)
        #expect(f.newcomer.summaries.map(\.title) == ["Messagerie exemple.fr"])
        try await f.approver.refreshDevices()
        #expect(f.approver.devices.count == 2)
        let added = try #require(f.approver.devices.first { !$0.isThisDevice })
        #expect(added.name == PairingFixture.newcomerName)
        #expect(added.addedBy == f.approver.thisDeviceID)
    }

    @Test func fullPairingWithAScannedQRWithoutSync() async throws {
        let f = try await PairingFixture(server: false)
        defer { f.cleanUp() }
        let (n, a, _) = try await f.compareHosted(mode: .personal, typed: false)
        await n.confirmCode()
        await a.approve(mode: .personal, password: testPassword)
        #expect(await eventually { n.state == .receivedFull })
        await n.importAndUnlock(password: testPassword)
        #expect(n.state == .done)
        #expect(f.newcomer.summaries.map(\.title) == ["Messagerie exemple.fr"])
    }

    @Test func codesAreRenewedAndEachHasItsOwnService() async throws {
        let f = try await PairingFixture(server: false)
        defer { f.cleanUp() }
        let (a, first) = try await f.host(renewEvery: .milliseconds(80))
        #expect(await eventually {
            if case .hosting(let code) = a.state { code.qrText != first.qrText } else { false }
        })
        #expect(first.qrText.hasPrefix("OPPAIR2:"))
        #expect(first.shortText.count == 9)
        #expect(try pairingRendezvousServiceName(code: first.shortText) == first.serviceName)
        #expect(f.network.publishedServices.contains(first.serviceName))
        // The older code still works until it expires.
        let n = PairingNewcomerFlow(
            vault: f.newcomer, mode: .personal, listener: f.network, deviceName: PairingFixture.newcomerName,
            deviceKind: .tablet)
        n.join(code: first.shortText, connector: f.network)
        #expect(await eventually { if case .comparing = a.state { true } else { false } })
        #expect(await eventually { if case .comparing = n.state { true } else { false } })
        a.cancel()
        n.cancel()
    }

    @Test func rejectingTheCodeSendsNothing() async throws {
        let f = try await PairingFixture(server: true)
        defer { f.cleanUp() }
        let (n, a, service) = try await f.compareHosted(mode: .personal)
        a.cancel()
        #expect(a.state == .failed(.codeRejected))
        #expect(await eventually {
            if case .failed = n.state { true } else { false }
        })
        // The new device only sent its Hello; the approver only its key exchange.
        #expect(f.network.frames(service: service, from: .connector).count == 1)
        #expect(f.network.frames(service: service, from: .listener).count == 1)
        await a.approve(mode: .personal, password: testPassword)
        try await f.approver.refreshDevices()
        #expect(f.approver.devices.count == 1)
        #expect(try storeState(dbPath: f.newcomerPath) == .empty)
    }

    @Test func cancelWhileShowingTheCodeWithdrawsIt() async throws {
        let f = try await PairingFixture(server: false)
        defer { f.cleanUp() }
        let (a, _) = try await f.host()
        a.cancel()
        #expect(a.state == .failed(.codeRejected))
    }

    @Test func aMalformedCodeEndsAtOnce() async throws {
        let f = try await PairingFixture(server: false)
        defer { f.cleanUp() }
        let n = PairingNewcomerFlow(vault: f.newcomer, mode: .personal, listener: f.network)
        n.join(code: "pas un code", connector: f.network)
        #expect(await eventually { n.state == .failed(.badCode) })
        #expect(PairingFailure.badCode.message.contains("8 caractères"))
    }

    @Test func aDeviceWithAnAccountCannotJoin() async throws {
        let f = try await PairingFixture(server: false)
        defer { f.cleanUp() }
        let n = PairingNewcomerFlow(vault: f.approver, mode: .personal, listener: f.network)
        n.join(code: "K7QM-4XPR", connector: f.network)
        #expect(n.state == .failed(.accountExists))
    }

    @Test func aLockedApproverCannotHost() async throws {
        let f = try await PairingFixture(server: false)
        defer { f.cleanUp() }
        f.approver.lock()
        let a = PairingApproverFlow(vault: f.approver, listener: f.network)
        a.startHosting()
        if case .failed = a.state {} else { Issue.record("hosting started on a locked vault: \(a.state)") }
    }

    /// Mac to iPhone over the real local network transport (loopback): the host publishes one Bonjour
    /// service per code, the new device finds it from the typed code alone and the whole pairing runs.
    @Test(.timeLimit(.minutes(3))) func fullPairingOverLocalNetwork() async throws {
        let f = try await PairingFixture(server: false)
        defer { f.cleanUp() }
        let a = PairingApproverFlow(vault: f.approver, listener: LocalNetworkPairingListener())
        a.startHosting()
        defer { a.cancel() }
        var shown: FfiHostCode?
        #expect(await eventually {
            if case .hosting(let code) = a.state { shown = code }
            return shown != nil
        })
        let code = try #require(shown)
        // Give Bonjour a moment to publish before the new device looks.
        try await Task.sleep(for: .seconds(1))
        let n = PairingNewcomerFlow(
            vault: f.newcomer, mode: .personal, listener: LocalNetworkPairingListener(),
            deviceName: PairingFlowTests.localName, deviceKind: .phone)
        n.join(code: code.shortText, connector: LocalNetworkPairingConnector(timeout: .seconds(20)))
        defer { n.cancel() }
        #expect(await eventually { if case .comparing = a.state { true } else if case .failed = n.state { true } else { false } })
        if case .failed(.hostNotFound) = n.state {
            try Test.cancel("Bonjour unavailable here: the pairing service could not be resolved on this Mac.")
        }
        guard case .comparing(let sas, let peer, _) = a.state else {
            Issue.record("approver not comparing: \(a.state), new device: \(n.state)")
            return
        }
        #expect(peer.name == PairingFlowTests.localName)
        #expect(await eventually { n.state == .comparing(sas: sas) })
        await n.confirmCode()
        await a.approve(mode: .personal, password: testPassword)
        #expect(await eventually { n.state == .receivedFull })
        await n.importAndUnlock(password: testPassword)
        #expect(n.state == .done)
        #expect(f.newcomer.summaries.map(\.title) == ["Messagerie exemple.fr"])
    }
}
