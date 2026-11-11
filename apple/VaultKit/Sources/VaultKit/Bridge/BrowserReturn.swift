import Foundation

/// Back to the browser after an unlock it asked for (MS-03, Mac): the extension brings the app forward
/// on its lock screen; once unlocked, the app hides itself so Safari (or Chrome) is in front again and
/// the extension resumes the fill. Only the activation changes; the unlock keeps its own policy.
///
/// Armed by the browser's request, consumed by the next unlock, dropped when the user opens the
/// window by hand or when the unlock comes too late (the extension stopped waiting).
///
/// Cold launch: the app was not running, so `onepass://unlock` starts it and Touch ID may answer
/// before the extension's bridge session exists. The link alone proves nothing (any page or app can
/// open it), so it never hides the app; but when a paired browser's request follows an unlock that
/// came after the link, within `lateWindow`, that request sends the app back as it would have before.
public struct BrowserReturn: Sendable, Equatable {
    /// About the time the extension waits for the unlock (its minute of polling) plus Touch ID.
    public static let window: TimeInterval = 90
    /// How long after a link's unlock the browser's own request still sends the app back.
    public static let lateWindow: TimeInterval = 10

    private var until: Date?
    /// The unlock link came in on a locked vault: its unlock may be the browser's.
    private var linkUntil: Date?
    /// Unlocked after the link, the browser's request not seen yet.
    private var lateUntil: Date?

    public init() {}

    /// The browser asked for an unlock now.
    public mutating func arm(now: Date = .now) {
        until = now.addingTimeInterval(Self.window)
    }

    /// `onepass://unlock` was opened on a locked vault.
    public mutating func linkOpened(now: Date = .now) {
        linkUntil = now.addingTimeInterval(Self.window)
    }

    /// The user went on in the app: no hiding after the unlock.
    public mutating func cancel() {
        until = nil
        linkUntil = nil
        lateUntil = nil
    }

    /// The vault unlocked: true when the browser asked for it lately. Consumed either way, so a later
    /// unlock never hides the app.
    public mutating func consume(now: Date = .now) -> Bool {
        defer {
            until = nil
            linkUntil = nil
        }
        lateUntil = nil
        if let until { return now <= until }
        if let linkUntil, now <= linkUntil { lateUntil = now.addingTimeInterval(Self.lateWindow) }
        return false
    }

    /// The browser asked for an unlock on a vault already open: true once, when that unlock followed
    /// the link lately (the request the unlock was waiting for).
    public mutating func confirmLate(now: Date = .now) -> Bool {
        defer { lateUntil = nil }
        guard let lateUntil else { return false }
        return now <= lateUntil
    }
}
