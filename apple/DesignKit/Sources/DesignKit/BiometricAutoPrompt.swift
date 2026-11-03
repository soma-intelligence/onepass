import SwiftUI

/// When the lock screen may ask for Face ID (Touch ID, Optic ID) on its own, and when the privacy
/// shield covers the window around that prompt. Plain state, no UI: `AppModel` feeds it the events
/// and the lock screen asks it.
///
/// The rule that makes a loop impossible: an automatic try belongs to a lock presentation
/// (`presentation`), and at most one is taken per presentation. A presentation begins only when the
/// vault actually locks, at launch, or on an explicit request to unlock (Mac). On iPhone, iPad and
/// Vision Pro no scene phase ever begins one: the system biometric sheet itself makes the scene
/// inactive and active again (and may report any burst of phases while it is up), so a rule fed by
/// scene phases takes the sheet for a return to the app and asks again, for ever (the cause of the
/// loop reverted in 3e4b39c2). Any prompt, automatic or tapped, spends the presentation's automatic
/// try: after it, only the Face ID button asks. Nothing that happens while the app's own prompt is
/// up, or while its sheet is leaving, begins a presentation.
///
/// The Mac keeps its rule that bringing the window forward asks again (its scenes do not leave the
/// front for Touch ID), except when the app left the front during its own prompt.
public struct BiometricAutoPrompt: Equatable, Sendable {
    /// The app's aggregate scene phase (mirrors SwiftUI's `ScenePhase`, so this stays testable
    /// without a UI).
    public enum Phase: Sendable {
        case active, inactive, background
    }

    /// Mac: a return to the front begins a presentation. Off on iPhone, iPad and Vision Pro.
    public let activationBeginsPresentation: Bool
    /// The current lock presentation. Starts at 1: a launch shows the lock screen for the first time.
    public private(set) var presentation: UInt64 = 1
    /// The presentation whose automatic try is spent (taken, or a prompt ran in it).
    private var spent: UInt64 = 0
    /// The app's own biometric prompt is up.
    public private(set) var promptRunning = false
    /// The prompt answered while the scene was not active yet (its sheet going away).
    private var promptLeaving = false
    /// The app left the front while its own prompt was on screen: the return is not an activation.
    private var awayForPrompt = false
    /// The next lock is the user's own (Verrouiller, Tout verrouiller): it begins a presentation
    /// without an automatic try, or Face ID would undo the lock at once.
    private var userLockPending = false

    public init(activationBeginsPresentation: Bool) {
        self.activationBeginsPresentation = activationBeginsPresentation
    }

    // MARK: - Events

    /// The vault went from unlocked to locked (auto-lock, a Control, Siri, the user, the Mac's
    /// screen lock). Never a failed or cancelled unlock: the vault was not open.
    public mutating func vaultLocked() {
        let byUser = userLockPending
        userLockPending = false
        beginPresentation(due: !byUser)
    }

    /// The user is about to lock the open vault from inside the app.
    public mutating func userWillLock() {
        userLockPending = true
    }

    /// An explicit request to unlock (Mac: "Déverrouiller dans OnePass").
    public mutating func unlockRequested() {
        beginPresentation(due: true)
    }

    /// The app's aggregate scene phase changed. On iPhone, iPad and Vision Pro this never makes an
    /// automatic try due: it only tracks the prompt's sheet for the privacy shield.
    public mutating func scenePhaseChanged(_ phase: Phase) {
        switch phase {
        case .active:
            if activationBeginsPresentation, !awayForPrompt, !promptOnScreen {
                beginPresentation(due: true)
            }
            awayForPrompt = false
            promptLeaving = false
        case .inactive:
            if promptOnScreen { awayForPrompt = true }
        case .background:
            if promptOnScreen { awayForPrompt = true }
            // The sheet is gone with the app; a prompt still running ends through `promptEnded`.
            promptLeaving = false
        }
    }

    /// The lock screen asks the system for a biometric check (automatic or tapped). It spends the
    /// presentation's automatic try.
    public mutating func promptStarted() {
        promptRunning = true
        promptLeaving = false
        spent = presentation
    }

    /// The check answered (success, cancel or failure); `sceneActive`: the scene is already active
    /// again. Never makes a try due.
    public mutating func promptEnded(sceneActive: Bool) {
        promptRunning = false
        promptLeaving = !sceneActive
    }

    // MARK: - Questions

    /// The lock screen may try once on its own now (without taking it).
    public var automaticAttemptDue: Bool {
        spent != presentation && !promptOnScreen
    }

    /// True at most once per presentation: the lock screen that asks may try on its own.
    public mutating func takeAutomaticAttempt() -> Bool {
        guard automaticAttemptDue else { return false }
        spent = presentation
        return true
    }

    /// The app's own prompt is up, or its sheet is still leaving.
    public var promptOnScreen: Bool { promptRunning || promptLeaving }

    /// The privacy shield covers the window: in the background always, while inactive unless the
    /// inactivity is the app's own biometric prompt over the lock screen (so the prompt rises over
    /// the lock screen and its dial, not a blank cover).
    public func shieldVisible(in phase: Phase) -> Bool {
        switch phase {
        case .active: false
        case .inactive: !promptOnScreen
        case .background: true
        }
    }

    /// How long the lock screen is on screen, active, before the automatic try: long enough to be
    /// seen (and for the shield to be gone), short enough not to feel like a wait.
    public static let settle: Duration = .milliseconds(450)

    // MARK: - Private

    private mutating func beginPresentation(due: Bool) {
        presentation &+= 1
        // Whatever happened around the app's own prompt, the user has just been asked.
        if !due || promptOnScreen { spent = presentation }
    }
}

extension BiometricAutoPrompt.Phase {
    /// SwiftUI's phase; an unknown future phase counts as not active (the shield covers it).
    public init(_ phase: ScenePhase) {
        switch phase {
        case .active: self = .active
        case .background: self = .background
        default: self = .inactive
        }
    }
}
