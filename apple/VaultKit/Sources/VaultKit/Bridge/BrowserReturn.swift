import Foundation

/// Back to the browser after an unlock it asked for (MS-03, Mac): the extension brings the app forward
/// on its lock screen; once unlocked, the app hides itself so Safari (or Chrome) is in front again and
/// the extension resumes the fill. Only the activation changes; the unlock keeps its own policy.
///
/// Armed by the browser's request, consumed by the next unlock, dropped when the user opens the
/// window by hand or when the unlock comes too late (the extension stopped waiting).
public struct BrowserReturn: Sendable, Equatable {
    /// About the time the extension waits for the unlock (its minute of polling) plus Touch ID.
    public static let window: TimeInterval = 90

    private var until: Date?

    public init() {}

    /// The browser asked for an unlock now.
    public mutating func arm(now: Date = .now) {
        until = now.addingTimeInterval(Self.window)
    }

    /// The user went on in the app: no hiding after the unlock.
    public mutating func cancel() {
        until = nil
    }

    /// The vault unlocked: true when the browser asked for it lately. Consumed either way, so a later
    /// unlock never hides the app.
    public mutating func consume(now: Date = .now) -> Bool {
        defer { until = nil }
        guard let until else { return false }
        return now <= until
    }
}
