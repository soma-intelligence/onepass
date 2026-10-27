import Foundation

/// A point on Earth, in degrees (WGS 84, as CoreLocation and MapKit give it).
public struct GeoPoint: Hashable, Sendable {
    public var latitude: Double
    public var longitude: Double

    public init(latitude: Double, longitude: Double) {
        self.latitude = latitude
        self.longitude = longitude
    }

    /// In range and not the editor's blank (0, 0): a location nobody placed is not a place.
    public var isPlaced: Bool {
        latitude.isFinite && longitude.isFinite && (-90...90).contains(latitude)
            && (-180...180).contains(longitude) && !(latitude == 0 && longitude == 0)
    }
}

/// An item of "À proximité": its summary and its distance to the user, in meters (closest of its places).
public struct NearbyItem: Equatable, Sendable {
    public var summary: FfiItemSummary
    public var distance: Double

    public init(summary: FfiItemSummary, distance: Double) {
        self.summary = summary
        self.distance = distance
    }
}

/// Item id to the places it holds (location fields, custom ones included, and the item's own
/// locations), so "À proximité" never decrypts the whole library on each render. An entry is kept
/// with the `updatedAt` of the summary it was read for: only new or modified items are read again.
/// `updatedAt` counts whole seconds, so an entry read during the second of its last edit may have
/// missed a second edit in that same second: it is read again until a read starts a later second.
///
/// Privacy: memory only, emptied on lock with the summaries. Coordinates never leave the device;
/// distances are computed here, never by a service.
public struct LocationIndex: Sendable {
    /// "À proximité" covers about 2 km around the user.
    public static let nearbyRadius: Double = 2_000

    public struct Entry: Equatable, Sendable {
        public var updatedAt: Int64
        public var points: [GeoPoint]
        /// Unix second when the read started (`Int64.max` for an entry known to be final, in tests).
        public var readAt: Int64

        public init(updatedAt: Int64, points: [GeoPoint], readAt: Int64 = .max) {
            self.updatedAt = updatedAt
            self.points = points
            self.readAt = readAt
        }

        /// Read for this version, after the second of its last edit had passed.
        func isCurrent(for updatedAt: Int64) -> Bool {
            self.updatedAt == updatedAt && readAt > updatedAt
        }
    }

    public private(set) var entries: [String: Entry] = [:]

    public init() {}

    /// Every placed point of an item: its location fields (template or custom), then its locations.
    public static func points(of item: FfiItem) -> [GeoPoint] {
        var out: [GeoPoint] = []
        for section in item.sections {
            for field in section.fields {
                if case .location(let l) = field.value { out.append(GeoPoint(latitude: l.lat, longitude: l.lon)) }
            }
        }
        out += item.locations.map { GeoPoint(latitude: $0.lat, longitude: $0.lon) }
        return out.filter(\.isPlaced)
    }

    /// The summaries whose entry is missing or older than the summary (to read before `nearby`).
    public func needsLoading(_ summaries: [FfiItemSummary]) -> [FfiItemSummary] {
        summaries.filter { entries[$0.id]?.isCurrent(for: $0.updatedAt) != true }
    }

    /// Stores the entries just read and drops those of items gone from `summaries`.
    public mutating func update(_ loaded: [String: Entry], keeping summaries: [FfiItemSummary]) {
        entries.merge(loaded) { _, new in new }
        let known = Set(summaries.map(\.id))
        entries = entries.filter { known.contains($0.key) }
    }

    /// Items of `summaries` with a place within `radius` meters of `origin`, closest first (then by title).
    public func nearby(_ summaries: [FfiItemSummary], from origin: GeoPoint, within radius: Double) -> [NearbyItem] {
        summaries.compactMap { summary -> NearbyItem? in
            guard let points = entries[summary.id]?.points, !points.isEmpty else { return nil }
            let closest = points.map { Self.distance(origin, $0) }.min() ?? .infinity
            return closest <= radius ? NearbyItem(summary: summary, distance: closest) : nil
        }
        .sorted { a, b in
            if a.distance != b.distance { return a.distance < b.distance }
            return a.summary.title.localizedStandardCompare(b.summary.title) == .orderedAscending
        }
    }

    /// Great-circle distance in meters (haversine, mean Earth radius): well under 1 % off at 2 km.
    public static func distance(_ a: GeoPoint, _ b: GeoPoint) -> Double {
        let earthRadius = 6_371_008.8
        let lat1 = a.latitude * .pi / 180
        let lat2 = b.latitude * .pi / 180
        let dLat = lat2 - lat1
        let dLon = (b.longitude - a.longitude) * .pi / 180
        let h = sin(dLat / 2) * sin(dLat / 2) + cos(lat1) * cos(lat2) * sin(dLon / 2) * sin(dLon / 2)
        return 2 * earthRadius * asin(min(1, sqrt(h)))
    }

    /// "à 350 m", "à 1,2 km" (French, rounded: 10 m steps under 1 km).
    public static func distanceLabel(_ meters: Double) -> String {
        if meters < 1_000 {
            let rounded = max(10, Int((meters / 10).rounded()) * 10)
            return rounded >= 1_000 ? "à 1 km" : "à \(rounded) m"
        }
        let km = (meters / 100).rounded() / 10
        let text = km == km.rounded() ? String(Int(km)) : String(format: "%.1f", km).replacingOccurrences(of: ".", with: ",")
        return "à \(text) km"
    }
}
