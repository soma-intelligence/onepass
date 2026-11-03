import SwiftUI

/// When the lock screen may ask for Face ID (Touch ID, Optic ID) on its own, and when the privacy
/// shield covers the window around that prompt.
///
/// On iPhone, iPad and Vision Pro the system biometric prompt makes the scene inactive while it is
/// up. Two things went wrong with that: the privacy shield (shown whenever the scene is not active)
/// covered the lock screen for the whole prompt, so the prompt always sat over a blank screen; and
/// the return to active after a cancel counted as a new activation, which armed another automatic
/// try. Here only a launch or a return from the background is an activation (the Mac, whose scenes
/// never go inactive for the prompt, counts every activation), and the shield stays down while the
/// app's own prompt is up and until the scene is active again after it.
public struct LockScreenActivation: Equatable, Sendable {
    /// Every return to active is a new activation (Mac). Off: only a launch or a return from the
    /// background is.
    public let activatesFromInactive: Bool
    /// One automatic try is due.
    public private(set) var armed = true
    /// The scene went to the background (or the app just launched) since the last activation.
    private var cameFromBackground = true
    /// The app's own biometric prompt is up.
    private var promptRunning = false
    /// The prompt ended while the scene was still inactive (its sheet going away).
    private var promptEndedInactive = false

    public init(activatesFromInactive: Bool) {
        self.activatesFromInactive = activatesFromInactive
    }

    /// The app's aggregate scene phase changed.
    public mutating func scenePhaseChanged(_ phase: ScenePhase) {
        switch phase {
        case .active:
            if cameFromBackground || activatesFromInactive { armed = true }
            cameFromBackground = false
            promptEndedInactive = false
        case .background:
            cameFromBackground = true
            promptRunning = false
            promptEndedInactive = false
        default:
            break
        }
    }

    /// An explicit request to unlock (Mac: "Déverrouiller dans OnePass"): one automatic try is due.
    public mutating func arm() { armed = true }

    /// True once per activation: the first lock screen that asks may try on its own.
    public mutating func take() -> Bool {
        defer { armed = false }
        return armed
    }

    /// The lock screen asks the system for a biometric check (automatic or tapped).
    public mutating func promptStarted() {
        promptRunning = true
        promptEndedInactive = false
    }

    /// The check answered; `sceneActive`: the scene is already active again.
    public mutating func promptEnded(sceneActive: Bool) {
        promptRunning = false
        promptEndedInactive = !sceneActive
    }

    /// The app's own prompt is up, or its sheet is still leaving.
    public var promptOnScreen: Bool { promptRunning || promptEndedInactive }

    /// The privacy shield covers the window: in the background always, while inactive unless the
    /// inactivity is the app's own biometric prompt over the lock screen.
    public func shieldVisible(in phase: ScenePhase) -> Bool {
        switch phase {
        case .active: false
        case .inactive: !promptOnScreen
        default: true
        }
    }

    /// How long the lock screen is on screen before the automatic try: long enough to be seen
    /// (and for the shield to be gone), short enough not to feel like a wait.
    public static let settle: Duration = .milliseconds(450)
}
