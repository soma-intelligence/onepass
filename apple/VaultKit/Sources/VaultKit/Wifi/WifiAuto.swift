import CryptoKit
import Foundation
import OnePassCore

// Wi-Fi automatique (spec docs/specs/2026-11-04-wifi-auto.md). The platform side (iOS
// NEHotspotConfiguration, macOS CoreWLAN) lives in the app; everything that decides lives here,
// testable without a radio. Nothing in this file logs an SSID or a password.

/// The Wi-Fi fields of a router item, read once from the decrypted item.
public struct WifiRouterInput: Sendable, Equatable {
    public var itemID: String
    public var vaultID: String
    /// `updated_at` of the item, Unix seconds (what the FFI carries).
    public var updatedAt: Int64
    public var archived: Bool
    public var trashed: Bool
    /// Hidden on this device by Travel Mode.
    public var travelHidden: Bool
    public var ssid: String
    public var password: String
    public var security: String
    public var hidden: String
    /// Where the router is: the item's placed locations (location fields and the item's own
    /// places). An iPhone installs a network on its own only near one of them.
    public var places: [GeoPoint]

    public init(
        itemID: String, vaultID: String, updatedAt: Int64 = 0, archived: Bool = false, trashed: Bool = false,
        travelHidden: Bool = false, ssid: String, password: String, security: String = "", hidden: String = "",
        places: [GeoPoint] = []
    ) {
        self.itemID = itemID
        self.vaultID = vaultID
        self.updatedAt = updatedAt
        self.archived = archived
        self.trashed = trashed
        self.travelHidden = travelHidden
        self.ssid = ssid
        self.password = password
        self.security = security
        self.hidden = hidden
        self.places = places
    }

    /// Nil for any item that is not a router.
    public init?(item: FfiItem) {
        guard item.itemType == .router else { return nil }
        func value(_ id: String) -> String {
            item.sections.flatMap(\.fields).first { $0.id == id }?.value.text ?? ""
        }
        self.init(
            itemID: item.id, vaultID: item.vaultId, updatedAt: item.updatedAt, archived: item.archived,
            trashed: item.trashedAt != nil, travelHidden: item.travelHidden, ssid: value("ssid"),
            password: value("wifi_password"), security: value("security"), hidden: value("hidden"),
            places: LocationIndex.points(of: item))
    }
}

/// Security of a network the device may join on its own, as in `onepass_core::wifi::Security`.
/// Open, WEP and enterprise networks never get one.
public enum WifiSecurity: String, Sendable, Codable, Equatable {
    /// WPA2 personal. Also the menu value "WPA" and an empty security with a password.
    case wpa2Personal = "wpa2-personal"
    /// WPA3 personal (SAE), and the WPA2/WPA3 transition mode.
    case wpa3Personal = "wpa3-personal"
}

/// Why a router item is not installed, as in `onepass_core::wifi::Skip` (plus `hidden`, an Apple
/// device rule). Never logged with the SSID.
public enum WifiSkip: Sendable, Equatable {
    case notRouter, inactive, noSSID, noPassword, open, wep, enterprise, badPassword
    /// In a vault hidden on this device or hidden by Travel Mode.
    case hidden
}

/// A network the device can install: one per SSID.
public struct WifiNetwork: Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible {
    public let itemID: String
    public let vaultID: String
    public let ssid: String
    public let password: String
    public let security: WifiSecurity
    public let hidden: Bool
    public let updatedAt: Int64
    /// The router item's places (never part of the fingerprint).
    public let places: [GeoPoint]

    public init(
        itemID: String, vaultID: String, ssid: String, password: String, security: WifiSecurity, hidden: Bool,
        updatedAt: Int64 = 0, places: [GeoPoint] = []
    ) {
        self.itemID = itemID
        self.vaultID = vaultID
        self.ssid = ssid
        self.password = password
        self.security = security
        self.hidden = hidden
        self.updatedAt = updatedAt
        self.places = places
    }

    /// Version of this network, the formula of `onepass_core::wifi::Network::fingerprint`: SHA-256
    /// (hex) of the item id, SSID, security, hidden flag and item `updated_at`. Never derived from
    /// the password (a hash of a Wi-Fi password is cheap to brute force); a changed password moves
    /// `updated_at`, so the version moves too. The FFI gives `updated_at` in seconds, so this equals
    /// the core's value only for an item saved on a whole second.
    public var fingerprint: String {
        var hasher = SHA256()
        hasher.update(data: Data("onepass-wifi-v1\u{0}".utf8))
        hasher.update(data: Self.idBytes(itemID))
        let ssidBytes = Data(ssid.utf8)
        withUnsafeBytes(of: UInt64(ssidBytes.count).bigEndian) { hasher.update(bufferPointer: $0) }
        hasher.update(data: ssidBytes)
        hasher.update(data: Data(security.rawValue.utf8))
        hasher.update(data: Data([hidden ? 1 : 0]))
        // i128 big endian of the nanoseconds: sign extension, then the 64-bit value.
        let nanos = updatedAt.multipliedReportingOverflow(by: 1_000_000_000)
        let low = nanos.overflow ? (updatedAt < 0 ? Int64.min : Int64.max) : nanos.partialValue
        withUnsafeBytes(of: UInt64(low < 0 ? UInt64.max : 0).bigEndian) { hasher.update(bufferPointer: $0) }
        withUnsafeBytes(of: UInt64(bitPattern: low).bigEndian) { hasher.update(bufferPointer: $0) }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    /// The 16 bytes of a UUID item id; the UTF-8 text of anything else (tests).
    static func idBytes(_ id: String) -> Data {
        guard let uuid = UUID(uuidString: id) else { return Data(id.utf8) }
        return withUnsafeBytes(of: uuid.uuid) { Data($0) }
    }

    /// Never the SSID nor the password (logs, crash reports, test failures).
    public var description: String { "WifiNetwork(item: \(itemID), security: \(security.rawValue))" }
    public var debugDescription: String { description }
}

/// Which router items a device joins on its own. The rules are those of `onepass_core::wifi`
/// (`classify`, `select`), rewritten here because the FFI does not export them yet: keep both in
/// step. A network qualifies with an SSID of 1 to 32 bytes and a WPA2 or WPA3 personal key; open,
/// WEP and enterprise networks never do (an open or enterprise network joined automatically is an
/// evil-twin target, WEP is broken), nor any security text the model does not know.
public enum WifiSelection {
    /// The network a router item describes, or why the device must not join it on its own.
    public static func network(_ input: WifiRouterInput, hiddenVaults: Set<String> = []) -> Result<WifiNetwork, WifiSkipError> {
        if input.archived || input.trashed { return .failure(.init(.inactive)) }
        if input.travelHidden || hiddenVaults.contains(input.vaultID) { return .failure(.init(.hidden)) }
        let ssid = input.ssid
        if ssid.isEmpty || ssid.utf8.count > 32 { return .failure(.init(.noSSID)) }
        let security = securityOf(input.security)
        // Open first: an open network with a stray password is still open.
        if security == .failure(.init(.open)) { return .failure(.init(.open)) }
        if input.password.isEmpty { return .failure(.init(.noPassword)) }
        let resolved: WifiSecurity
        switch security {
        case .success(let value): resolved = value
        case .failure(let why): return .failure(why)
        }
        guard isValidPassphrase(input.password) else { return .failure(.init(.badPassword)) }
        return .success(WifiNetwork(
            itemID: input.itemID, vaultID: input.vaultID, ssid: ssid, password: input.password,
            security: resolved, hidden: isYes(input.hidden), updatedAt: input.updatedAt, places: input.places))
    }

    /// Every network to install, one per SSID: the most recently edited item wins a duplicate SSID,
    /// equal times keep the lower item id. Sorted by SSID (bytes, as the core's `BTreeMap`).
    public static func networks(_ inputs: [WifiRouterInput], hiddenVaults: Set<String> = []) -> [WifiNetwork] {
        var best: [String: WifiNetwork] = [:]
        for input in inputs {
            guard case .success(let n) = network(input, hiddenVaults: hiddenVaults) else { continue }
            if let current = best[n.ssid] {
                let newer = n.updatedAt > current.updatedAt
                    || (n.updatedAt == current.updatedAt && n.itemID < current.itemID)
                if !newer { continue }
            }
            best[n.ssid] = n
        }
        return best.values.sorted { Array($0.ssid.utf8).lexicographicallyPrecedes(Array($1.ssid.utf8)) }
    }

    /// Security of a router menu value (or free text from an import), as `security_of` in the core.
    static func securityOf(_ raw: String) -> Result<WifiSecurity, WifiSkipError> {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if ["entreprise", "enterprise", "802.1x", "eap", "radius"].contains(where: s.contains) {
            return .failure(.init(.enterprise))
        }
        switch s {
        case "", "wpa", "wpa2", "wpa/wpa2", "wpa2 personnel", "wpa2 personal", "wpa2-psk", "wpa2psk":
            return .success(.wpa2Personal)
        case "wpa3", "wpa2/wpa3", "wpa3 personnel", "wpa3 personal", "wpa3-sae", "sae":
            return .success(.wpa3Personal)
        case "wep":
            return .failure(.init(.wep))
        case "ouvert", "open", "aucune", "aucun", "none", "nopass":
            return .failure(.init(.open))
        default:
            return .failure(.init(.enterprise))
        }
    }

    /// WPA personal key: 8 to 63 printable ASCII characters, or 64 hexadecimal digits (a raw key).
    static func isValidPassphrase(_ p: String) -> Bool {
        let bytes = Array(p.utf8)
        if bytes.count == 64 {
            return bytes.allSatisfy { ($0 >= 48 && $0 <= 57) || ($0 | 0x20 >= 97 && $0 | 0x20 <= 102) }
        }
        return (8...63).contains(bytes.count) && bytes.allSatisfy { $0 >= 0x20 && $0 <= 0x7E }
    }

    static func isYes(_ s: String) -> Bool {
        ["oui", "yes", "true"].contains(s.trimmingCharacters(in: .whitespacesAndNewlines).lowercased())
    }
}

public struct WifiSkipError: Error, Equatable, Sendable {
    public let reason: WifiSkip
    public init(_ reason: WifiSkip) { self.reason = reason }
}

// MARK: - What the device already has

/// What happened to one network handed to the system.
public enum WifiInstallOutcome: Sendable, Equatable {
    /// Saved (or already there with these values).
    case installed
    /// The user said no to the system's question: not asked again until the item changes.
    case declined
    /// The system refused these values for good (bad SSID or passphrase): retried after an edit.
    case rejected
    /// Anything transient (busy, internal error): retried at the next activation.
    case failed
}

/// The device's record of what it applied, by item: the fingerprint (no secret in it) and the
/// outcome. Also the SSIDs the Mac already saved to the vault (or the user undid), hashed. Lives in
/// the keychain, this device only, never synced: it tells which networks this device has.
public struct WifiLedger: Codable, Sendable, Equatable {
    public struct Entry: Codable, Sendable, Equatable {
        public var fingerprint: String
        public var outcome: String
        /// Unix second of a transient failure ("failed" only).
        public var failedAt: Int64?
    }

    /// A transient failure is tried again after this many seconds, not at each launch: iOS
    /// answers "unable to join" for a network out of range, and a retry per launch was a loop.
    public static let retryDelay: Int64 = 6 * 3600

    public var applied: [String: Entry] = [:]
    public var capturedSSIDs: Set<String> = []

    public init() {}

    /// Networks new or changed since the last outcome recorded for their item, and transient
    /// failures of this same version once `retryDelay` has passed.
    public func pending(_ networks: [WifiNetwork], now: Int64 = Int64(Date().timeIntervalSince1970)) -> [WifiNetwork] {
        networks.filter { network in
            guard let entry = applied[network.itemID], entry.fingerprint == network.fingerprint else { return true }
            guard entry.outcome == "failed" else { return false }
            return now - (entry.failedAt ?? 0) >= Self.retryDelay
        }
    }

    /// Records an outcome. A transient failure is kept with its time, so it waits `retryDelay`.
    public mutating func record(
        _ network: WifiNetwork, _ outcome: WifiInstallOutcome, now: Int64 = Int64(Date().timeIntervalSince1970)
    ) {
        let entry: Entry
        switch outcome {
        case .installed: entry = Entry(fingerprint: network.fingerprint, outcome: "installed")
        case .declined: entry = Entry(fingerprint: network.fingerprint, outcome: "declined")
        case .rejected: entry = Entry(fingerprint: network.fingerprint, outcome: "rejected")
        case .failed: entry = Entry(fingerprint: network.fingerprint, outcome: "failed", failedAt: now)
        }
        applied[network.itemID] = entry
    }

    public func outcome(of itemID: String) -> String? { applied[itemID]?.outcome }

    // Device to vault (macOS).

    public static func ssidKey(_ ssid: String) -> String {
        SHA256.hash(data: Data(("wifi-ssid-v1\u{0}" + ssid).utf8)).map { String(format: "%02x", $0) }.joined()
    }

    public func wasCaptured(_ ssid: String) -> Bool { capturedSSIDs.contains(Self.ssidKey(ssid)) }
    public mutating func markCaptured(_ ssid: String) { capturedSSIDs.insert(Self.ssidKey(ssid)) }
}

public protocol WifiLedgerStore: Sendable {
    /// Nil when the store cannot be read right now (keychain locked): the caller does nothing,
    /// since an empty ledger would hand every network to the system again (and ask again).
    func load() -> WifiLedger?
    func save(_ ledger: WifiLedger)
}

/// The ledger in the keychain (this device only, not synced).
public struct KeychainWifiLedgerStore: WifiLedgerStore {
    public static let key = "wifi.ledger.v1"
    private let keychain: any KeychainStore

    public init(keychain: any KeychainStore) { self.keychain = keychain }

    public func load() -> WifiLedger? {
        let data: Data?
        do { data = try keychain.read(Self.key) } catch { return nil }
        // Never written, or unreadable after a format change: start over (each network asked once more).
        guard let data, let ledger = try? JSONDecoder().decode(WifiLedger.self, from: data) else { return WifiLedger() }
        return ledger
    }

    public func save(_ ledger: WifiLedger) {
        guard let data = try? JSONEncoder().encode(ledger) else { return }
        try? keychain.writeAfterFirstUnlock(Self.key, data)
    }
}

// MARK: - Vault to device

/// The system that installs networks: NEHotspotConfiguration on iOS, CoreWLAN on macOS, a fake in
/// tests. It handles the batch in order and may stop early (an unanswered or refused system
/// question): networks without a result stay pending.
public protocol WifiInstaller: Sendable {
    func install(_ networks: [WifiNetwork]) async -> [(WifiNetwork, WifiInstallOutcome)]
}

public struct WifiSyncReport: Sendable, Equatable {
    public var attempted = 0
    public var installed = 0
    public var declined = 0
    public init() {}
}

/// The device's position for one pass: a point and its horizontal accuracy in meters (negative
/// means invalid, as in CoreLocation).
public struct WifiPosition: Sendable, Equatable {
    public var point: GeoPoint
    public var accuracy: Double

    public init(point: GeoPoint, accuracy: Double) {
        self.point = point
        self.accuracy = accuracy
    }
}

/// iPhone and iPad: installing a network makes iOS try to join it at once, so a network is handed
/// to the system only when the device is near the router. The position is compared here, on the
/// device, and never sent anywhere.
public enum WifiProximity {
    /// A router counts as near within this many meters of one of its places.
    public static let radius: Double = 200
    /// A fix vaguer than this cannot tell 150 m from 2 km: nothing counts as near.
    public static let maxAccuracy: Double = 200

    public static func isNear(_ places: [GeoPoint], _ position: WifiPosition?) -> Bool {
        guard let position, position.accuracy >= 0, position.accuracy <= maxAccuracy else { return false }
        return places.contains { LocationIndex.distance(position.point, $0) <= radius }
    }
}

/// Which networks a pass may hand to the system.
public enum WifiProximityRule: Sendable, Equatable {
    /// Every pending network (Mac: a saved profile joins nothing by itself).
    case everywhere
    /// Only pending networks with a place near this position (iPhone, iPad). Nil: none.
    case near(WifiPosition?)
}

public enum WifiAutoSync {
    /// Installs what is new or changed and records each outcome. Unchanged items are never handed
    /// to the system again (idempotent), whatever their last outcome; a transient failure waits
    /// `WifiLedger.retryDelay`. Under `.near`, a network not near stays pending with no outcome.
    public static func run(
        inputs: [WifiRouterInput], hiddenVaults: Set<String>, store: any WifiLedgerStore, installer: any WifiInstaller,
        proximity: WifiProximityRule = .everywhere, now: Int64 = Int64(Date().timeIntervalSince1970)
    ) async -> WifiSyncReport {
        var report = WifiSyncReport()
        guard let before = store.load() else { return report }
        var pending = before.pending(WifiSelection.networks(inputs, hiddenVaults: hiddenVaults), now: now)
        if case .near(let position) = proximity {
            pending = pending.filter { WifiProximity.isNear($0.places, position) }
        }
        guard !pending.isEmpty else { return report }
        report.attempted = pending.count
        let results = await installer.install(pending)
        // Read again: the install may have waited on a system question for a while.
        var ledger = store.load() ?? before
        for (network, outcome) in results {
            ledger.record(network, outcome, now: now)
            if outcome == .installed { report.installed += 1 }
            if outcome == .declined { report.declined += 1 }
        }
        store.save(ledger)
        return report
    }

    /// Whether a `.near` pass has anything to compare: a pending network with a place. False
    /// means the position is not asked for (no permission prompt, no fix).
    public static func needsPosition(
        inputs: [WifiRouterInput], hiddenVaults: Set<String>, store: any WifiLedgerStore,
        now: Int64 = Int64(Date().timeIntervalSince1970)
    ) -> Bool {
        guard let ledger = store.load() else { return false }
        return ledger.pending(WifiSelection.networks(inputs, hiddenVaults: hiddenVaults), now: now)
            .contains { !$0.places.isEmpty }
    }

    /// "Rejoindre" in a router item: hands that one network to the system now, whatever the switch
    /// and the distance (the user asked), and records the outcome. Nil when the item is not a
    /// network the device may join (no SSID, open, WEP, enterprise...) or the ledger is locked.
    public static func join(
        itemID: String, inputs: [WifiRouterInput], store: any WifiLedgerStore, installer: any WifiInstaller,
        now: Int64 = Int64(Date().timeIntervalSince1970)
    ) async -> WifiInstallOutcome? {
        guard let input = inputs.first(where: { $0.itemID == itemID }),
            case .success(let network) = WifiSelection.network(input), store.load() != nil
        else { return nil }
        guard let outcome = await installer.install([network]).first?.1 else { return nil }
        guard var ledger = store.load() else { return outcome }
        ledger.record(network, outcome, now: now)
        store.save(ledger)
        return outcome
    }
}

// MARK: - Device to vault (macOS)

/// A network the Mac joined, read from the system (password from the System keychain).
public struct WifiJoined: Sendable, Equatable, CustomStringConvertible {
    public let ssid: String
    public let password: String
    public let security: WifiSecurity

    public init(ssid: String, password: String, security: WifiSecurity) {
        self.ssid = ssid
        self.password = password
        self.security = security
    }

    public var description: String { "WifiJoined(security: \(security.rawValue))" }

    /// The router item's fields, in the template's ids and menu values.
    public var fields: [(id: String, value: FfiFieldValue)] {
        let label = switch security {
        case .wpa3Personal: "WPA3"
        case .wpa2Personal: "WPA2"
        }
        return [
            ("ssid", .text(value: ssid)),
            ("wifi_password", .password(value: password)),
            ("security", .menu(value: label)),
            ("hidden", .menu(value: "non")),
        ]
    }
}

public enum WifiCapture {
    /// Whether the Mac should save the network it is on: a personal network with a password, not
    /// already in the vault under that SSID, and never saved (or undone) on this device before.
    public static func shouldCapture(_ joined: WifiJoined?, vaultSSIDs: Set<String>, ledger: WifiLedger) -> Bool {
        guard let joined, isCandidate(ssid: joined.ssid, vaultSSIDs: vaultSSIDs, ledger: ledger) else { return false }
        return WifiSelection.isValidPassphrase(joined.password)
    }

    /// The same test before the password is read (reading it may show a system prompt): a network
    /// already in the vault or already handled never causes one.
    public static func isCandidate(ssid: String, vaultSSIDs: Set<String>, ledger: WifiLedger) -> Bool {
        guard !ssid.isEmpty, ssid.utf8.count <= 32 else { return false }
        return !vaultSSIDs.contains(ssid) && !ledger.wasCaptured(ssid)
    }

    /// Every SSID of the vault's router items (archived ones too; the trash does not count), so a
    /// network already saved, even open or enterprise, is never saved twice.
    public static func vaultSSIDs(_ inputs: [WifiRouterInput]) -> Set<String> {
        Set(inputs.filter { !$0.trashed && !$0.ssid.isEmpty }.map(\.ssid))
    }
}

/// macOS commits a whole configuration: a list read without the Location permission has profiles
/// without SSID, and committing it would erase the user's networks. The installer adds only to a
/// list it fully read.
public enum WifiProfileMerge {
    public static func canCommit(existing: [Data?]) -> Bool { !existing.contains(nil) }

    /// The SSIDs to add, in order, without the ones already listed.
    public static func toAdd(existing: [Data], networks: [WifiNetwork]) -> [WifiNetwork] {
        let known = Set(existing)
        var seen = Set<Data>()
        return networks.filter {
            let d = Data($0.ssid.utf8)
            return !known.contains(d) && seen.insert(d).inserted
        }
    }
}

extension VaultSession {
    /// The Wi-Fi fields of every router item of the vaults this session sees, read without
    /// touching the recents (a background job, not the user opening items).
    public func wifiRouterInputs() async throws -> [WifiRouterInput] {
        let refs = summaries.filter { $0.itemType == .router }.map { ($0.vaultId, $0.id) }
        guard !refs.isEmpty else { return [] }
        return try await read { session in
            refs.compactMap { vaultID, itemID in
                (try? session.item(vaultId: vaultID, itemId: itemID)).flatMap(WifiRouterInput.init(item:))
            }
        }
    }
}
