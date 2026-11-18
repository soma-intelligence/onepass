import SwiftUI

/// The only haptic vocabulary an app uses (UX-HAPT-01). Each event maps to one
/// fixed `SensoryFeedback`, so the same event feels the same everywhere.
///
/// Haptics confirm user-caused events only: never on scroll, on appear or for
/// marketing, and at most one per gesture (UX-HAPT-02). `sensoryFeedback`
/// already respects the system haptics setting (UX-HAPT-03).
public enum DBHapticEvent: String, Sendable, Hashable, CaseIterable {
    /// Picker, segment or toggle tick.
    case selection
    /// Snapping, drag pickup, pull-to-refresh threshold.
    case snap
    /// Drop or commit.
    case commit
    /// Completed task, payment sent, copied.
    case success
    /// Validation blocked.
    case warning
    /// Failure.
    case error
    /// Stepper up.
    case increase
    /// Stepper down.
    case decrease
    /// Slider detent.
    case levelChange

    public var feedback: SensoryFeedback {
        switch self {
        case .selection: .selection
        case .snap: .impact(weight: .light)
        case .commit: .impact(weight: .medium)
        case .success: .success
        case .warning: .warning
        case .error: .error
        case .increase: .increase
        case .decrease: .decrease
        case .levelChange: .levelChange
        }
    }

    /// The haptic paired with a toast (UX-TOAST-05). Info toasts stay silent.
    public static func forToast(_ kind: DBToastKind) -> DBHapticEvent? {
        switch kind {
        case .success: .success
        case .error: .error
        case .info: nil
        }
    }
}

public extension View {
    /// Plays `event` each time `trigger` changes. The one entry point for haptics.
    func dbHaptic<T: Equatable>(_ event: DBHapticEvent, trigger: T) -> some View {
        sensoryFeedback(event.feedback, trigger: trigger)
    }

    /// Picks the event from the change of `trigger`; return nil to stay silent.
    func dbHaptic<T: Equatable>(
        trigger: T,
        _ event: @escaping (_ oldValue: T, _ newValue: T) -> DBHapticEvent?
    ) -> some View {
        sensoryFeedback(trigger: trigger) { old, new in
            event(old, new)?.feedback
        }
    }
}
