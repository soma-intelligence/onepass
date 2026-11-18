import Foundation

public enum DBToastKind: String, Sendable, Hashable, CaseIterable {
    case success
    case info
    case error

    /// SF Symbol shown before the message.
    public var systemImage: String {
        switch self {
        case .success: "checkmark.circle.fill"
        case .info: "info.circle.fill"
        case .error: "exclamationmark.triangle.fill"
        }
    }
}

/// A button inside a toast, such as Undo or Retry. Tapping it runs the handler
/// and dismisses the toast.
public struct DBToastButton: Sendable {
    public let title: String
    public let handler: @MainActor @Sendable () -> Void

    public init(_ title: String, handler: @escaping @MainActor @Sendable () -> Void) {
        self.title = title
        self.handler = handler
    }
}

/// Display times (UX-TOAST-02).
public enum DBToastTiming {
    /// Success confirmations: 1.8 s, clamped to 1.5 to 2 s.
    public static let success: TimeInterval = 1.8
    public static let successRange: ClosedRange<TimeInterval> = 1.5...2
    /// Info: 2.5 s, clamped to 1.5 to 4 s.
    public static let info: TimeInterval = 2.5
    public static let infoRange: ClosedRange<TimeInterval> = 1.5...4
    /// A success or info toast with an action (Undo): 5 s, clamped to 4 to 6 s.
    public static let withAction: TimeInterval = 5
    public static let actionRange: ClosedRange<TimeInterval> = 4...6
    /// Errors stay at least 6 s; a longer request is honoured.
    public static let errorMinimum: TimeInterval = 6

    /// How much longer toasts stay under a DesignBridge UI test (`DB_UI_TESTING=1`, Debug only):
    /// 3x, so an XCUITest snapshot of a large screen, which can take more than a second, still
    /// finds a 1.8 s confirmation. 1 everywhere else, so the rule above holds for people.
    public static let uiTestingScale: TimeInterval = {
        #if DEBUG
        ProcessInfo.processInfo.environment["DB_UI_TESTING"] == "1" ? 3 : 1
        #else
        1
        #endif
    }()

    /// The display time for a toast, with `requested` clamped to the rule.
    public static func duration(kind: DBToastKind, hasAction: Bool, requested: TimeInterval? = nil) -> TimeInterval {
        switch kind {
        case .error:
            return max(requested ?? errorMinimum, errorMinimum)
        case .success, .info:
            if hasAction {
                return (requested ?? withAction).clamped(to: actionRange)
            }
            if kind == .success {
                return (requested ?? success).clamped(to: successRange)
            }
            return (requested ?? info).clamped(to: infoRange)
        }
    }
}

/// One toast. Build it with the factories:
///
/// ```swift
/// toast(.success("Copied"))
/// toast(.undo("Item deleted") { restore() })
/// toast(.error("Couldn't save. Check your connection.", action: DBToastButton("Retry") { save() }))
/// ```
public struct DBToast: Identifiable, Sendable {
    /// Accessibility identifier of the visible toast, the one `DBUITestCase.assertToast` finds.
    public static let accessibilityIdentifier = "db.toast"

    public let id: UUID
    public let kind: DBToastKind
    /// 1 to 3 words for confirmations; what happened plus the fix for errors.
    public let message: String
    public let systemImage: String
    public let action: DBToastButton?
    /// Resolved display time in seconds.
    public let duration: TimeInterval

    public init(
        kind: DBToastKind,
        message: String,
        systemImage: String? = nil,
        action: DBToastButton? = nil,
        duration: TimeInterval? = nil
    ) {
        self.id = UUID()
        self.kind = kind
        self.message = message
        self.systemImage = systemImage ?? kind.systemImage
        self.action = action
        self.duration = DBToastTiming.duration(kind: kind, hasAction: action != nil, requested: duration)
    }

    public static func success(_ message: String, systemImage: String? = nil, action: DBToastButton? = nil) -> DBToast {
        DBToast(kind: .success, message: message, systemImage: systemImage, action: action)
    }

    public static func info(_ message: String, systemImage: String? = nil, action: DBToastButton? = nil) -> DBToast {
        DBToast(kind: .info, message: message, systemImage: systemImage, action: action)
    }

    /// An error is never silent: it stays at least 6 s.
    public static func error(
        _ message: String,
        systemImage: String? = nil,
        action: DBToastButton? = nil,
        duration: TimeInterval? = nil
    ) -> DBToast {
        DBToast(kind: .error, message: message, systemImage: systemImage, action: action, duration: duration)
    }

    /// A reversible action confirmed with an Undo button, shown 5 s (UX-ACT-05).
    public static func undo(
        _ message: String,
        undoTitle: String = DBStrings.undo,
        systemImage: String? = nil,
        perform undo: @escaping @MainActor @Sendable () -> Void
    ) -> DBToast {
        DBToast(kind: .success, message: message, systemImage: systemImage, action: DBToastButton(undoTitle, handler: undo))
    }

    /// A failure the person can try again from a Retry button. Stays at least 6 s.
    public static func retry(
        _ message: String,
        retryTitle: String = DBStrings.retry,
        systemImage: String? = nil,
        perform retry: @escaping @MainActor @Sendable () -> Void
    ) -> DBToast {
        DBToast(kind: .error, message: message, systemImage: systemImage, action: DBToastButton(retryTitle, handler: retry))
    }

    /// Two toasts are duplicates when they would read the same.
    func isDuplicate(of other: DBToast) -> Bool {
        kind == other.kind && message == other.message && action?.title == other.action?.title
    }
}

extension Comparable {
    func clamped(to range: ClosedRange<Self>) -> Self {
        min(max(self, range.lowerBound), range.upperBound)
    }
}
