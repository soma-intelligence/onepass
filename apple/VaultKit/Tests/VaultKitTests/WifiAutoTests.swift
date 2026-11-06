import CryptoKit
import Foundation
import Synchronization
import Testing

@testable import VaultKit

/// Installer double: answers from a table, records every batch it was handed.
private final class FakeInstaller: WifiInstaller {
    let batches = Mutex<[[String]]>([])
    let answers: [String: WifiInstallOutcome]
    /// Stops after the first network with this outcome (a refused system question).
    let stopOn: WifiInstallOutcome?

    init(_ answers: [String: WifiInstallOutcome] = [:], stopOn: WifiInstallOutcome? = nil) {
        self.answers = answers
        self.stopOn = stopOn
    }

    func install(_ networks: [WifiNetwork]) async -> [(WifiNetwork, WifiInstallOutcome)] {
        batches.withLock { $0.append(networks.map(\.ssid)) }
        var out: [(WifiNetwork, WifiInstallOutcome)] = []
        for n in networks {
            let outcome = answers[n.ssid] ?? .installed
            out.append((n, outcome))
            if let stopOn, outcome == stopOn { break }
        }
        return out
    }

    var handed: [[String]] { batches.withLock { $0 } }
}

private final class MemoryLedgerStore: WifiLedgerStore {
    let ledger = Mutex(WifiLedger())
    func load() -> WifiLedger? { ledger.withLock { $0 } }
    func save(_ l: WifiLedger) { ledger.withLock { $0 = l } }
}

private struct LockedLedgerStore: WifiLedgerStore {
    func load() -> WifiLedger? { nil }
    func save(_ ledger: WifiLedger) { Issue.record("a locked ledger is never written") }
}

/// A keychain that cannot be read (device locked).
private struct ThrowingKeychain: KeychainStore {
    struct Locked: Error {}
    func read(_ key: String) throws -> Data? { throw Locked() }
    func write(_ key: String, _ data: Data) throws { throw Locked() }
    func delete(_ key: String) throws { throw Locked() }
    func contains(_ key: String) throws -> Bool { throw Locked() }
}

private func router(
    _ id: String, ssid: String, password: String = "Prairie-Soleil-90", security: String = "WPA2",
    hidden: String = "non", vault: String = "v1", updatedAt: Int64 = 1, archived: Bool = false, trashed: Bool = false
) -> WifiRouterInput {
    WifiRouterInput(
        itemID: id, vaultID: vault, updatedAt: updatedAt, archived: archived, trashed: trashed, ssid: ssid,
        password: password, security: security, hidden: hidden)
}

@Suite("Wi-Fi automatique: selection")
struct WifiSelectionTests {
    private func reason(_ input: WifiRouterInput, hidden: Set<String> = []) -> WifiSkip? {
        if case .failure(let e) = WifiSelection.network(input, hiddenVaults: hidden) { return e.reason }
        return nil
    }

    @Test func personalNetworksQualify() throws {
        // The table of `security_of` in onepass_core::wifi.
        for (security, expected) in [
            ("WPA3", WifiSecurity.wpa3Personal), ("WPA2", .wpa2Personal), ("WPA", .wpa2Personal),
            (" wpa2 ", .wpa2Personal), ("wpa2-psk", .wpa2Personal), ("WPA/WPA2", .wpa2Personal),
            ("WPA2/WPA3", .wpa3Personal), ("SAE", .wpa3Personal), ("wpa3-sae", .wpa3Personal), ("", .wpa2Personal),
        ] {
            let n = try WifiSelection.network(router("a", ssid: "Maison", security: security)).get()
            #expect(n.security == expected, "security \(security)")
            #expect(n.ssid == "Maison")
        }
    }

    @Test func openWepAndEnterpriseAreSkipped() {
        #expect(reason(router("a", ssid: "Gare", security: "Ouvert")) == .open)
        #expect(reason(router("a", ssid: "Gare", security: "open")) == .open)
        #expect(reason(router("a", ssid: "Gare", password: "mot-de-passe-perdu", security: "Ouvert")) == .open)
        #expect(reason(router("a", ssid: "Gare", password: "", security: "")) == .noPassword)
        #expect(reason(router("a", ssid: "Gare", password: "", security: "WPA2")) == .noPassword)
        #expect(reason(router("a", ssid: "Vieux", security: "WEP")) == .wep)
        #expect(reason(router("a", ssid: "Bureau", security: "WPA2-Enterprise")) == .enterprise)
        #expect(reason(router("a", ssid: "Bureau", security: "WPA2 Entreprise")) == .enterprise)
        #expect(reason(router("a", ssid: "Campus", security: "802.1X EAP")) == .enterprise)
        // A security the model does not know is never guessed as personal.
        #expect(reason(router("a", ssid: "Etrange", security: "Mystery")) == .enterprise)
        #expect(reason(router("a", ssid: "Etrange", security: "WPA2-TKIP")) == .enterprise)
    }

    @Test func badValuesAreSkipped() {
        #expect(reason(router("a", ssid: "")) == .noSSID)
        #expect(reason(router("a", ssid: String(repeating: "x", count: 33))) == .noSSID)
        #expect(reason(router("a", ssid: String(repeating: "x", count: 32))) == nil)
        #expect(reason(router("a", ssid: "Court", password: "1234567")) == .badPassword)
        #expect(reason(router("a", ssid: "Long", password: String(repeating: "a", count: 65))) == .badPassword)
        #expect(reason(router("a", ssid: "Accent", password: "mot-de-passe-été")) == .badPassword)
        #expect(reason(router("a", ssid: "Tab", password: "tab\there!")) == .badPassword)
        // 64 hex digits: a raw PSK.
        let hex = String(repeating: "0aF9", count: 16)
        #expect(reason(router("a", ssid: "Hex", password: hex)) == nil)
        #expect(reason(router("a", ssid: "NotHex", password: String(repeating: "g", count: 64))) == .badPassword)
    }

    @Test func archivedTrashedAndHiddenVaultsAreSkipped() {
        #expect(reason(router("a", ssid: "A", archived: true)) == .inactive)
        #expect(reason(router("a", ssid: "A", trashed: true)) == .inactive)
        #expect(reason(router("a", ssid: "A", vault: "hidden"), hidden: ["hidden"]) == .hidden)
        var travel = router("a", ssid: "A")
        travel.travelHidden = true
        #expect(reason(travel) == .hidden)
    }

    @Test func hiddenFlagIsRead() throws {
        #expect(try WifiSelection.network(router("a", ssid: "A", hidden: "oui")).get().hidden)
        #expect(try WifiSelection.network(router("a", ssid: "A", hidden: " Yes ")).get().hidden)
        #expect(try !WifiSelection.network(router("a", ssid: "A", hidden: "non")).get().hidden)
        #expect(try !WifiSelection.network(router("a", ssid: "A", hidden: "1")).get().hidden)
    }

    @Test func oneNetworkPerSSIDTheNewestWins() {
        let list = WifiSelection.networks([
            router("old", ssid: "Maison", password: "ancien-mot-de-passe", updatedAt: 10),
            router("new", ssid: "Maison", password: "nouveau-mot-de-passe", updatedAt: 20),
            router("other", ssid: "Atelier", updatedAt: 5),
            router("open", ssid: "Gare", security: "Ouvert"),
        ])
        #expect(list.map(\.ssid) == ["Atelier", "Maison"])
        #expect(list.last?.itemID == "new")
        // Equal times keep the lower item id, whatever the order.
        for order in [["b", "a"], ["a", "b"]] {
            let tie = WifiSelection.networks(order.map { router($0, ssid: "Maison", updatedAt: 7) })
            #expect(tie.map(\.itemID) == ["a"])
        }
    }

    @Test func fingerprintIsTheCoreOneAndHasNoPassword() throws {
        let id = "01890a5d-ac96-774b-bcce-b302099a8057"
        let a = try WifiSelection.network(router(id, ssid: "Maison", updatedAt: 1_700_000_000)).get()
        #expect(a.fingerprint.count == 64)
        // The password alone does not enter it...
        let otherPassword = try WifiSelection.network(
            router(id, ssid: "Maison", password: "autre-mot-de-passe", updatedAt: 1_700_000_000)).get()
        #expect(a.fingerprint == otherPassword.fingerprint)
        // ...the update time, the SSID, the security and the hidden flag do.
        let changed = try [
            router(id, ssid: "Maison", updatedAt: 1_700_000_001), router(id, ssid: "Maison2", updatedAt: 1_700_000_000),
            router(id, ssid: "Maison", security: "WPA3", updatedAt: 1_700_000_000),
            router(id, ssid: "Maison", hidden: "oui", updatedAt: 1_700_000_000),
        ].map { try WifiSelection.network($0).get().fingerprint }
        #expect(Set(changed + [a.fingerprint]).count == 5)
        // `onepass_core::wifi::Network::fingerprint` of the same router (id, "Maison", WPA2, not
        // hidden, updated at 1_700_000_000 s), printed by the core itself on 2026-11-04.
        let core = "050bc6d77f45a01d4ed4435bebae1dbcd29f42e3c35cabbcb25dae49ea472471"
        #expect(a.fingerprint == core)
        #expect(coreFingerprint(id: id, ssid: "Maison", security: "wpa2-personal", hidden: false, seconds: 1_700_000_000) == core)
    }

    /// The core's formula, written out separately so a drift in either shows.
    private func coreFingerprint(id: String, ssid: String, security: String, hidden: Bool, seconds: Int64) -> String {
        var bytes = Array("onepass-wifi-v1".utf8) + [0]
        let uuid = UUID(uuidString: id)!.uuid
        bytes += withUnsafeBytes(of: uuid) { Array($0) }
        let s = Array(ssid.utf8)
        bytes += withUnsafeBytes(of: UInt64(s.count).bigEndian) { Array($0) } + s
        bytes += Array(security.utf8) + [hidden ? 1 : 0]
        bytes += [UInt8](repeating: 0, count: 8) + withUnsafeBytes(of: UInt64(seconds * 1_000_000_000).bigEndian) { Array($0) }
        return SHA256.hash(data: Data(bytes)).map { String(format: "%02x", $0) }.joined()
    }

    @Test func descriptionsNeverCarryTheSSIDOrPassword() throws {
        let n = try WifiSelection.network(router("a", ssid: "Maison-Durand", password: "Prairie-Soleil-90")).get()
        for text in [String(describing: n), String(reflecting: n), "\(n)"] {
            #expect(!text.contains("Maison-Durand"))
            #expect(!text.contains("Prairie-Soleil-90"))
        }
        let joined = WifiJoined(ssid: "Maison-Durand", password: "Prairie-Soleil-90", security: .wpa2Personal)
        #expect(!"\(joined)".contains("Maison-Durand"))
        #expect(!"\(joined)".contains("Prairie"))
    }
}

@Suite("Wi-Fi automatique: vault to device")
struct WifiAutoSyncTests {
    @Test func installsOnceThenNeverAgain() async {
        let store = MemoryLedgerStore()
        let installer = FakeInstaller()
        let inputs = [router("a", ssid: "Maison"), router("b", ssid: "Atelier")]
        let first = await WifiAutoSync.run(inputs: inputs, hiddenVaults: [], store: store, installer: installer)
        #expect(first.installed == 2)
        let second = await WifiAutoSync.run(inputs: inputs, hiddenVaults: [], store: store, installer: installer)
        #expect(second.attempted == 0)
        #expect(installer.handed == [["Atelier", "Maison"]])
    }

    @Test func aChangedPasswordIsAppliedAgainAndOnlyThatOne() async {
        let store = MemoryLedgerStore()
        let installer = FakeInstaller()
        _ = await WifiAutoSync.run(
            inputs: [router("a", ssid: "Maison"), router("b", ssid: "Atelier")], hiddenVaults: [], store: store,
            installer: installer)
        _ = await WifiAutoSync.run(
            inputs: [router("a", ssid: "Maison", password: "nouveau-mot-de-passe", updatedAt: 2), router("b", ssid: "Atelier")],
            hiddenVaults: [], store: store, installer: installer)
        #expect(installer.handed == [["Atelier", "Maison"], ["Maison"]])
    }

    @Test func aLockedLedgerHandsNothingToTheSystem() async {
        let installer = FakeInstaller()
        let report = await WifiAutoSync.run(
            inputs: [router("a", ssid: "Maison")], hiddenVaults: [], store: LockedLedgerStore(), installer: installer)
        #expect(report.attempted == 0)
        #expect(installer.handed.isEmpty)
    }

    @Test func aLockedKeychainReadsAsLocked() {
        #expect(KeychainWifiLedgerStore(keychain: ThrowingKeychain()).load() == nil)
        #expect(KeychainWifiLedgerStore(keychain: InMemoryKeychain()).load() == WifiLedger())
    }

    @Test func aDeclinedNetworkIsNotAskedAgainUntilItChanges() async {
        let store = MemoryLedgerStore()
        let installer = FakeInstaller(["Maison": .declined], stopOn: .declined)
        let report = await WifiAutoSync.run(
            inputs: [router("a", ssid: "Maison"), router("b", ssid: "Zinc")], hiddenVaults: [], store: store,
            installer: installer)
        #expect(report.declined == 1)
        #expect(store.load()?.outcome(of: "a") == "declined")
        // Zinc was never answered: still pending; Maison is not asked again.
        _ = await WifiAutoSync.run(
            inputs: [router("a", ssid: "Maison"), router("b", ssid: "Zinc")], hiddenVaults: [], store: store,
            installer: FakeInstaller())
        let next = FakeInstaller()
        _ = await WifiAutoSync.run(
            inputs: [router("a", ssid: "Maison", password: "nouveau-mot-de-passe", updatedAt: 2)], hiddenVaults: [],
            store: store, installer: next)
        #expect(next.handed == [["Maison"]])
    }

    @Test func transientFailuresAreRetriedRejectionsAreNot() async {
        let store = MemoryLedgerStore()
        let inputs = [router("a", ssid: "Busy"), router("b", ssid: "Refused")]
        _ = await WifiAutoSync.run(
            inputs: inputs, hiddenVaults: [], store: store,
            installer: FakeInstaller(["Busy": .failed, "Refused": .rejected]))
        let again = FakeInstaller()
        _ = await WifiAutoSync.run(inputs: inputs, hiddenVaults: [], store: store, installer: again)
        #expect(again.handed == [["Busy"]])
    }

    @Test func openEnterpriseAndWepNeverReachTheSystem() async {
        let store = MemoryLedgerStore()
        let installer = FakeInstaller()
        let report = await WifiAutoSync.run(
            inputs: [
                router("a", ssid: "Gare", security: "Ouvert"), router("b", ssid: "Bureau", security: "WPA2-Enterprise"),
                router("c", ssid: "Vieux", security: "WEP"), router("d", ssid: "Gratuit", password: ""),
            ], hiddenVaults: [], store: store, installer: installer)
        #expect(report.attempted == 0)
        #expect(installer.handed.isEmpty)
    }

    @Test func ledgerRoundTripsThroughTheKeychain() {
        let keychain = InMemoryKeychain()
        let store = KeychainWifiLedgerStore(keychain: keychain)
        var ledger = WifiLedger()
        let n = WifiNetwork(itemID: "a", vaultID: "v", ssid: "Maison", password: "Prairie-Soleil-90", security: .wpa2Personal, hidden: false)
        ledger.record(n, .installed)
        ledger.markCaptured("Atelier")
        store.save(ledger)
        #expect(store.load() == ledger)
        #expect(keychain.isAfterFirstUnlock(KeychainWifiLedgerStore.key))
        // Neither the SSID nor the password is stored in clear.
        let raw = String(decoding: (try? keychain.read(KeychainWifiLedgerStore.key)) ?? Data(), as: UTF8.self)
        #expect(!raw.contains("Maison"))
        #expect(!raw.contains("Atelier"))
        #expect(!raw.contains("Prairie"))
    }
}

@Suite("Wi-Fi automatique: device to vault")
struct WifiCaptureTests {
    let joined = WifiJoined(ssid: "Cafe-Lumiere", password: "croissant-chaud-7", security: .wpa2Personal)

    @Test func aNewPersonalNetworkIsCaptured() {
        #expect(WifiCapture.shouldCapture(joined, vaultSSIDs: ["Maison"], ledger: WifiLedger()))
    }

    @Test func knownCapturedOrUnreadableNetworksAreNot() {
        #expect(!WifiCapture.shouldCapture(nil, vaultSSIDs: [], ledger: WifiLedger()))
        #expect(!WifiCapture.shouldCapture(joined, vaultSSIDs: ["Cafe-Lumiere"], ledger: WifiLedger()))
        var ledger = WifiLedger()
        ledger.markCaptured("Cafe-Lumiere")
        #expect(!WifiCapture.shouldCapture(joined, vaultSSIDs: [], ledger: ledger))
        let noPassword = WifiJoined(ssid: "Gare", password: "", security: .wpa2Personal)
        #expect(!WifiCapture.shouldCapture(noPassword, vaultSSIDs: [], ledger: WifiLedger()))
    }

    @Test func vaultSSIDsCountArchivedAndOpenButNotTrashed() {
        let ssids = WifiCapture.vaultSSIDs([
            router("a", ssid: "Archive", archived: true), router("b", ssid: "Gare", security: "Ouvert"),
            router("c", ssid: "Jete", trashed: true),
        ])
        #expect(ssids == ["Archive", "Gare"])
    }

    @Test func fieldsUseTheTemplateMenuValues() {
        let fields = Dictionary(uniqueKeysWithValues: joined.fields.map { ($0.id, $0.value) })
        #expect(fields["ssid"] == .text(value: "Cafe-Lumiere"))
        #expect(fields["wifi_password"] == .password(value: "croissant-chaud-7"))
        #expect(fields["security"] == .menu(value: "WPA2"))
        #expect(WifiJoined(ssid: "x", password: "y", security: .wpa3Personal).fields.first { $0.id == "security" }?.value == .menu(value: "WPA3"))
    }

    @Test func aPartiallyReadListIsNeverCommitted() {
        #expect(WifiProfileMerge.canCommit(existing: [Data("A".utf8), Data("B".utf8)]))
        #expect(!WifiProfileMerge.canCommit(existing: [Data("A".utf8), nil]))
    }

    @Test func onlyMissingNetworksAreAdded() {
        let a = WifiNetwork(itemID: "1", vaultID: "v", ssid: "A", password: "Prairie-Soleil-90", security: .wpa2Personal, hidden: false)
        let b = WifiNetwork(itemID: "2", vaultID: "v", ssid: "B", password: "Prairie-Soleil-90", security: .wpa2Personal, hidden: false)
        #expect(WifiProfileMerge.toAdd(existing: [Data("A".utf8)], networks: [a, b]).map(\.ssid) == ["B"])
    }
}

@MainActor
@Suite("Wi-Fi automatique: router items of a session", .serialized)
struct WifiSessionTests {
    @Test func routerItemsAreReadWithoutTouchingRecents() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        let vault = session.allVaults[0].id
        var item = try session.newItem(type: .router, vaultID: vault)
        item.title = "Wi-Fi Maison"
        for s in item.sections.indices {
            for f in item.sections[s].fields.indices {
                switch item.sections[s].fields[f].id {
                case "ssid": item.sections[s].fields[f].value = .text(value: "Maison-Test")
                case "wifi_password": item.sections[s].fields[f].value = .password(value: "Prairie-Soleil-Nuage-90")
                case "security": item.sections[s].fields[f].value = .menu(value: "WPA3")
                default: break
                }
            }
        }
        let saved = try await session.save(item)
        var login = try session.newItem(type: .login, vaultID: vault)
        login.title = "Atlas"
        fillRequired(&login)
        _ = try await session.save(login)
        let recentsBefore = session.recents

        let inputs = try await session.wifiRouterInputs()
        #expect(inputs.count == 1)
        #expect(inputs.first?.itemID == saved.id)
        #expect(inputs.first?.ssid == "Maison-Test")
        #expect(inputs.first?.security == "WPA3")
        #expect(session.recents == recentsBefore)
        let networks = WifiSelection.networks(inputs)
        #expect(networks.first?.security == .wpa3Personal)
    }
}
