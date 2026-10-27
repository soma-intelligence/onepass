import Foundation

public struct GlanceStore: Sendable {
    private let directory: URL

    public init(directory: URL) {
        self.directory = directory
    }

    /// App Group container + "Library/OnePass"; nil when the group is unavailable.
    public static func shared() -> GlanceStore? {
        guard let container = AppGroup.containerURL() else { return nil }
        return GlanceStore(directory: container.appendingPathComponent("Library/OnePass", isDirectory: true))
    }

    private var fileURL: URL { directory.appendingPathComponent("glance.json") }

    public func write(_ snapshot: GlanceSnapshot) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        let data = try encoder.encode(snapshot)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        #if os(iOS) || os(watchOS) || os(visionOS)
            try data.write(to: fileURL, options: [.atomic, .completeFileProtection])
        #else
            try data.write(to: fileURL, options: [.atomic])
        #endif
    }

    public func read(now: Date = .now) -> GlanceSnapshot? {
        guard let data = try? Data(contentsOf: fileURL) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        guard let snapshot = try? decoder.decode(GlanceSnapshot.self, from: data),
            now < snapshot.validUntil
        else { return nil }
        return snapshot
    }

    /// What a widget can show: the snapshot, "locked" when the file exists but cannot be read
    /// (data protection while the device is locked), or "stale" when it is absent, expired or
    /// corrupt (the app must publish a new one).
    public enum Status: Sendable, Hashable {
        case available(GlanceSnapshot)
        case locked
        case stale
    }

    public func status(now: Date = .now) -> Status {
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return .stale }
        guard let data = try? Data(contentsOf: fileURL) else { return .locked }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        guard let snapshot = try? decoder.decode(GlanceSnapshot.self, from: data),
            now < snapshot.validUntil
        else { return .stale }
        return .available(snapshot)
    }

    public func clear() {
        try? FileManager.default.removeItem(at: fileURL)
    }
}
