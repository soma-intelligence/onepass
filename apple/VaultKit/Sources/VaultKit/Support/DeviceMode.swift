import Foundation

public enum DeviceMode: String, Codable, Sendable {
    case personal
    case shared

    public var biometricsAllowed: Bool { self == .personal }

    /// Auto-lock imposed by the mode, in seconds (5 minutes on a shared device).
    public var forcedAutoLock: TimeInterval? { self == .shared ? 300 : nil }
}
