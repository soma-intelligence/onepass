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
///
/// Touch ID first (Mac, `biometricsFirst`): the automatic try runs at once, and the lock screen
/// shows only its glyph and title while it is due or up; the password column appears once it
/// answers without unlocking. A browser's unlock request while the app is not in front asks Touch
/// ID over the browser (`browserUnlockRoute`); only a refusal brings the window forward, on the
/// password column (`directPromptRefused`).
public struct BiometricAutoPrompt: Equatable, Sendable {
    /// The app's aggregate scene phase (mirrors SwiftUI's `ScenePhase`, so this stays testable
    /// without a UI).
    public enum Phase: Sendable {
        case active, inactive, background
    }

    /// Mac: a return to the front begins a presentation. Off on iPhone, iPad and Vision Pro.
    public let activationBeginsPresentation: Bool
    /// Mac: the system prompt comes before the password column, with no settle. Off on iPhone,
    /// iPad and Vision Pro.
    public let biometricsFirst: Bool
    /// The current lock presentation. Starts at 1: a launch shows the lock screen for the first time.
    public private(set) var presentation: UInt64 = 1
    /// The presentation whose automatic try is spent (taken, or a prompt ran in it).
    private var spent: UInt64 = 0
    /// The app's own biometric prompt is up.
    public private(set) var promptRunning = false
    /// The prompt up is an automatic one (the lock screen's own try, or Touch ID over the browser),
    /// not the Touch ID button's.
    public private(set) var automaticPromptRunning = false
    /// The prompt answered while the scene was not active yet (its sheet going away).
    private var promptLeaving = false
    /// The app left the front while its own prompt was on screen: the return is not an activation.
    private var awayForPrompt = false
    /// The next lock is the user's own (Verrouiller, Tout verrouiller): it begins a presentation
    /// without an automatic try, or Face ID would undo the lock at once.
    private var userLockPending = false
    /// Touch ID asked over the browser was refused and the window is coming forward for the
    /// password: that return to the front is not an activation that asks again.
    private var activationHeld = false

    public init(activationBeginsPresentation: Bool, biometricsFirst: Bool = false) {
        self.activationBeginsPresentation = activationBeginsPresentation
        self.biometricsFirst = biometricsFirst
    }

    /// How the app answers a browser's unlock request on a locked vault.
    public enum BrowserUnlockRoute: Equatable, Sendable {
        /// The system prompt runs over the browser; the window stays where it is.
        case direct
        /// The window comes forward on the lock screen (which asks on its own when due).
        case window
        /// The app's own prompt is up already: it answers this request too.
        case asking
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
            if activationBeginsPresentation, !awayForPrompt, !promptOnScreen, !activationHeld {
                beginPresentation(due: true)
            }
            activationHeld = false
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
    public mutating func promptStarted(automatic: Bool = true) {
        promptRunning = true
        automaticPromptRunning = automatic
        promptLeaving = false
        spent = presentation
    }

    /// The check answered (success, cancel or failure); `sceneActive`: the scene is already active
    /// again. Never makes a try due.
    public mutating func promptEnded(sceneActive: Bool) {
        promptRunning = false
        automaticPromptRunning = false
        promptLeaving = !sceneActive
    }

    /// Touch ID asked over the browser (`BrowserUnlockRoute.direct`) answered without unlocking
    /// (cancel, failure, password due): a presentation without an automatic try begins, and the
    /// return to the front that follows does not make one due.
    public mutating func directPromptRefused() {
        beginPresentation(due: false)
        activationHeld = true
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

    /// Whether the lock screen shows its password column now. With `biometricsFirst`, a lock
    /// screen that can use biometrics shows only its glyph and title while the automatic try is
    /// due, while an automatic prompt is up, and while its own automatic check (`checking`) starts.
    /// The Touch ID button's prompt keeps the column it belongs to. `ready`: the lock screen can
    /// take the try now (on screen, in an active scene, the Mac awake and its screen unlocked); a try
    /// that is due but cannot be taken never hides the column, or the screen would offer nothing.
    public func showsPasswordColumn(canUseBiometrics: Bool, checking: Bool, ready: Bool = true) -> Bool {
        Self.showsPasswordColumn(
            biometricsFirst: biometricsFirst, canUseBiometrics: canUseBiometrics,
            attemptDue: automaticAttemptDue, promptRunning: automaticPromptRunning, checking: checking,
            ready: ready)
    }

    /// `showsPasswordColumn` with the due state given (the app may veto it in captures);
    /// `promptRunning`: an automatic prompt is up.
    public static func showsPasswordColumn(
        biometricsFirst: Bool, canUseBiometrics: Bool, attemptDue: Bool, promptRunning: Bool, checking: Bool,
        ready: Bool = true
    ) -> Bool {
        guard biometricsFirst, canUseBiometrics else { return true }
        return !((attemptDue && ready) || promptRunning || checking)
    }

    /// A browser asks to unlock the locked vault. With `biometricsFirst`, while the app is not in
    /// front and biometrics can be used, the prompt runs over the browser.
    public func browserUnlockRoute(appActive: Bool, canUseBiometrics: Bool) -> BrowserUnlockRoute {
        if promptRunning { return .asking }
        return biometricsFirst && !appActive && canUseBiometrics ? .direct : .window
    }

    /// How long the lock screen waits before its automatic try: none with `biometricsFirst`.
    public var settleDelay: Duration { biometricsFirst ? .zero : Self.settle }

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
