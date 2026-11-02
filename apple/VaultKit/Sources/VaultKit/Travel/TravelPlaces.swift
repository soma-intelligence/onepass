import CryptoKit
import Foundation

/// Geohash of a position (spec 2026-11-02 travel detection, section 6): computed on the device, no
/// geocoder. Precision 3 is a cell of about 156 by 156 km at the equator.
public enum Geohash {
    private static let alphabet = Array("0123456789bcdefghjkmnpqrstuvwxyz")

    public static func encode(latitude: Double, longitude: Double, precision: Int) -> String {
        var lat = (-90.0, 90.0)
        var lon = (-180.0, 180.0)
        var even = true
        var bit = 0
        var ch = 0
        var out = ""
        let latitude = min(max(latitude, -90), 90)
        var longitude = longitude.truncatingRemainder(dividingBy: 360)
        if longitude >= 180 { longitude -= 360 } else if longitude < -180 { longitude += 360 }
        while out.count < precision {
            if even {
                let mid = (lon.0 + lon.1) / 2
                if longitude >= mid { ch |= 1 << (4 - bit); lon.0 = mid } else { lon.1 = mid }
            } else {
                let mid = (lat.0 + lat.1) / 2
                if latitude >= mid { ch |= 1 << (4 - bit); lat.0 = mid } else { lat.1 = mid }
            }
            even.toggle()
            if bit < 4 {
                bit += 1
            } else {
                out.append(alphabet[ch])
                bit = 0
                ch = 0
            }
        }
        return out
    }

    /// The cell's bounds: (south, north, west, east). `nil` for a character outside the alphabet.
    public static func bounds(_ hash: String) -> (Double, Double, Double, Double)? {
        var lat = (-90.0, 90.0)
        var lon = (-180.0, 180.0)
        var even = true
        for c in hash {
            guard let value = alphabet.firstIndex(of: c) else { return nil }
            for i in stride(from: 4, through: 0, by: -1) {
                let on = (value >> i) & 1 == 1
                if even {
                    let mid = (lon.0 + lon.1) / 2
                    if on { lon.0 = mid } else { lon.1 = mid }
                } else {
                    let mid = (lat.0 + lat.1) / 2
                    if on { lat.0 = mid } else { lat.1 = mid }
                }
                even.toggle()
            }
        }
        return (lat.0, lat.1, lon.0, lon.1)
    }

    /// The cell and its 8 neighbours (fewer at a pole), longitude wrapped.
    public static func neighbourhood(_ hash: String) -> Set<String> {
        guard let (s, n, w, e) = bounds(hash) else { return [hash] }
        let height = n - s
        let width = e - w
        let lat = (s + n) / 2
        let lon = (w + e) / 2
        var out: Set<String> = []
        for dy in -1...1 {
            let y = lat + Double(dy) * height
            guard y > -90, y < 90 else { continue }
            for dx in -1...1 {
                out.insert(encode(latitude: y, longitude: lon + Double(dx) * width, precision: hash.count))
            }
        }
        return out
    }
}

/// What the device learned about where its owner usually is, and where the current trip stands.
/// Never synced, never sent: `TravelPlacesStore` keeps it in an encrypted local file.
public struct TravelPlaces: Codable, Equatable, Sendable {
    /// Cell to the days (since 1970, UTC) it was seen, at most `TravelDetector.windowDays` back.
    public var seen: [String: [Int]] = [:]
    /// Cells the owner taught with "No, I'm not travelling".
    public var taught: Set<String> = []
    /// "Not now" on this trip: quiet until the device is home again.
    public var tripSnoozed = false
    /// The trip's notification was posted: only one per trip.
    public var tripNotified = false
    /// Travel Mode on and home again: the "back home?" card was dismissed.
    public var welcomeDismissed = false
    /// The trip's suggestion waits for an answer (the card shows it, even after a relaunch from the
    /// notification).
    public var pendingCell: String?
    /// Travel Mode was on at the last check: a background check (no unlocked vault) reads it.
    public var travelActive = false
    /// Last check (seconds since 1970), for the throttle.
    public var lastCheck: Double?

    public init() {}

    public var isEmpty: Bool { seen.isEmpty && taught.isEmpty }
}

/// The detector's answer for one position.
public enum TravelVerdict: Equatable, Sendable {
    /// Not enough days observed yet: nothing is suggested.
    case learning
    /// In or next to a usual cell.
    case home
    /// Far from every usual cell.
    case away(cell: String)
}

/// What the app should show after a check.
public enum TravelSuggestion: Equatable, Sendable {
    case none
    /// "Are you travelling?" (`notify`: post the one notification of this trip too).
    case suggest(cell: String, notify: Bool)
    /// Travel Mode is on and the device is home again.
    case welcomeBack
}

/// Pure rules of the travel detection (spec 2026-11-02, section 6). No location, no clock, no I/O.
public enum TravelDetector {
    public static let precision = 3
    /// Days a cell must be seen on before it is usual.
    public static let usualDays = 3
    /// Days of history kept per cell.
    public static let windowDays = 60
    /// Most cells kept (the least recently seen go first).
    public static let maxCells = 64
    /// Distinct days observed overall before anything is suggested.
    public static let minObservedDays = 3
    /// Seconds between two foreground checks.
    public static let throttle: Double = 3 * 3600

    public static func cell(latitude: Double, longitude: Double) -> String {
        Geohash.encode(latitude: latitude, longitude: longitude, precision: precision)
    }

    public static func usualCells(_ places: TravelPlaces) -> Set<String> {
        var out = places.taught
        for (cell, days) in places.seen where Set(days).count >= usualDays { out.insert(cell) }
        return out
    }

    public static func verdict(_ places: TravelPlaces, cell: String) -> TravelVerdict {
        let usual = usualCells(places)
        if !usual.isDisjoint(with: Geohash.neighbourhood(cell)) { return .home }
        let days = Set(places.seen.values.flatMap { $0 })
        if days.count < minObservedDays && places.taught.isEmpty { return .learning }
        return .away(cell: cell)
    }

    /// Remember that the device was in `cell` on `day`, trimming old days and cells.
    public static func observe(_ places: inout TravelPlaces, cell: String, day: Int) {
        var days = places.seen[cell] ?? []
        if !days.contains(day) { days.append(day) }
        places.seen[cell] = days
        for (key, value) in places.seen {
            let kept = value.filter { $0 > day - windowDays }
            places.seen[key] = kept.isEmpty ? nil : kept
        }
        if places.seen.count > maxCells {
            let order = places.seen.sorted { ($0.value.max() ?? 0) < ($1.value.max() ?? 0) }
            for (key, _) in order.prefix(places.seen.count - maxCells) { places.seen[key] = nil }
        }
    }

    /// One check: the suggestion for `cell`, then the observation (a trip in Travel Mode teaches
    /// nothing). Home again ends the trip (snooze and notification flags reset).
    public static func check(
        _ places: inout TravelPlaces, cell: String, day: Int, travelling: Bool
    ) -> TravelSuggestion {
        let verdict = verdict(places, cell: cell)
        if !travelling { observe(&places, cell: cell, day: day) }
        switch verdict {
        case .home:
            places.tripSnoozed = false
            places.tripNotified = false
            places.pendingCell = nil
            if travelling, !places.welcomeDismissed { return .welcomeBack }
            return .none
        case .learning:
            return .none
        case .away(let cell):
            places.welcomeDismissed = false
            if travelling || places.tripSnoozed {
                places.pendingCell = nil
                return .none
            }
            let notify = !places.tripNotified
            places.tripNotified = true
            places.pendingCell = cell
            return .suggest(cell: cell, notify: notify)
        }
    }

    /// "No, I'm not travelling": the cell becomes usual.
    public static func teach(_ places: inout TravelPlaces, cell: String) {
        places.taught.insert(cell)
        places.pendingCell = nil
    }

    /// "Not now": quiet until home.
    public static func snooze(_ places: inout TravelPlaces) {
        places.tripSnoozed = true
        places.pendingCell = nil
    }

    /// "Yes": Travel Mode handles the trip from here.
    public static func accepted(_ places: inout TravelPlaces) {
        places.pendingCell = nil
        places.travelActive = true
    }
}

/// `TravelPlaces` in a local file, sealed with AES-GCM under a key kept in the keychain
/// (`WhenUnlockedThisDeviceOnly`): never synced, excluded from backups, unreadable without the
/// device's keychain. `wipe` forgets both.
public struct TravelPlacesStore: Sendable {
    public static let keyName = "travel.places.key"

    public let url: URL
    public let keychain: any KeychainStore

    public init(url: URL, keychain: any KeychainStore) {
        self.url = url
        self.keychain = keychain
    }

    /// Application Support/OnePass/travel-places.bin of this app (not the shared container: the
    /// extensions never need it).
    public static func defaultURL() throws -> URL {
        let base = try FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        return base.appendingPathComponent("OnePass", isDirectory: true)
            .appendingPathComponent("travel-places.bin")
    }

    /// The places, or empty ones when there is no file, no key, or the file does not open (it is
    /// then forgotten: learning starts again).
    public func load() -> TravelPlaces {
        guard let sealed = try? Data(contentsOf: url), let keyData = try? keychain.read(Self.keyName),
            let box = try? AES.GCM.SealedBox(combined: sealed),
            let plain = try? AES.GCM.open(box, using: SymmetricKey(data: keyData)),
            let places = try? JSONDecoder().decode(TravelPlaces.self, from: plain)
        else { return TravelPlaces() }
        return places
    }

    public func save(_ places: TravelPlaces) throws {
        let keyData: Data
        if let existing = try keychain.read(Self.keyName) {
            keyData = existing
        } else {
            keyData = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
            try keychain.write(Self.keyName, keyData)
        }
        let plain = try JSONEncoder().encode(places)
        let sealed = try AES.GCM.seal(plain, using: SymmetricKey(data: keyData))
        guard let combined = sealed.combined else { throw CocoaError(.fileWriteUnknown) }
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        #if os(iOS) || os(watchOS) || os(visionOS)
        try combined.write(to: url, options: [.atomic, .completeFileProtection])
        #else
        try combined.write(to: url, options: [.atomic])
        #endif
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var target = url
        try? target.setResourceValues(values)
    }

    /// Forget every learned place: the file and its key.
    public func wipe() throws {
        if FileManager.default.fileExists(atPath: url.path) {
            try FileManager.default.removeItem(at: url)
        }
        try keychain.delete(Self.keyName)
    }
}
