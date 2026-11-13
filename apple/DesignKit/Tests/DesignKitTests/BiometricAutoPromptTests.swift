import Testing
@testable import DesignKit

/// The lock screen's automatic Face ID: at most one try per lock presentation, whatever scene phases
/// the system sheet causes (the loop reverted in 3e4b39c2).
@Suite("Biometric auto prompt")
struct BiometricAutoPromptTests {
    /// Plays the lock screen the way `LockView` does: on every event it asks, when the scene is
    /// active, whether a try is due, takes it and raises the prompt; the prompt answers later.
    private struct LockScreen {
        var gate: BiometricAutoPrompt
        var phase: BiometricAutoPrompt.Phase = .active
        var automaticAttempts = 0
        var promptUp = false

        init(mac: Bool = false) {
            gate = BiometricAutoPrompt(activationBeginsPresentation: mac)
        }

        /// The lock screen's task: it runs again on each phase change and each new presentation.
        mutating func lockScreenTask() {
            guard phase == .active, !promptUp else { return }
            if gate.automaticAttemptDue, gate.takeAutomaticAttempt() {
                automaticAttempts += 1
                gate.promptStarted()
                promptUp = true
            }
        }

        mutating func phase(_ new: BiometricAutoPrompt.Phase) {
            phase = new
            gate.scenePhaseChanged(new)
            lockScreenTask()
        }

        /// The system answers the prompt (success, cancel or failure: the gate sees the same).
        mutating func answer() {
            precondition(promptUp)
            promptUp = false
            gate.promptEnded(sceneActive: phase == .active)
            lockScreenTask()
        }

        /// The Face ID button.
        mutating func tapFaceID() {
            guard !promptUp else { return }
            gate.promptStarted()
            promptUp = true
        }

        mutating func vaultLocked() {
            gate.vaultLocked()
            lockScreenTask()
        }
    }

    // MARK: - One try per presentation

    @Test func launchTriesOnce() {
        var gate = BiometricAutoPrompt(activationBeginsPresentation: false)
        #expect(gate.automaticAttemptDue)
        #expect(take(&gate))
        #expect(!take(&gate))
        #expect(!gate.automaticAttemptDue)
    }

    /// The device sequence of the loop: the sheet makes the scene inactive, then active, possibly
    /// several times while it is up and as it leaves. Exactly one automatic try.
    /// Success, cancel and failure end the same way for the gate.
    @Test func inactiveActiveBurstsDuringThePromptTryOnce() {
        var screen = LockScreen()
        screen.lockScreenTask()
        #expect(screen.automaticAttempts == 1)
        for _ in 0..<20 {
            screen.phase(.inactive)
            screen.phase(.active)
        }
        screen.phase(.inactive)
        screen.answer()
        for _ in 0..<20 {
            screen.phase(.active)
            screen.phase(.inactive)
        }
        screen.phase(.active)
        #expect(screen.automaticAttempts == 1)
        #expect(!screen.gate.automaticAttemptDue)
    }

    /// Even a background report while the sheet is up (or as it leaves) begins nothing.
    @Test func backgroundBurstsAroundThePromptTryOnce() {
        var screen = LockScreen()
        screen.lockScreenTask()
        screen.phase(.inactive)
        screen.phase(.background)
        screen.phase(.inactive)
        screen.phase(.active)
        screen.phase(.inactive)
        screen.answer()
        screen.phase(.background)
        screen.phase(.inactive)
        screen.phase(.active)
        #expect(screen.automaticAttempts == 1)
    }

    /// No automatic retry after the prompt ends, while the scene is active again either.
    @Test func noRetryAfterTheAnswer() {
        var screen = LockScreen()
        screen.lockScreenTask()
        screen.phase(.inactive)
        screen.phase(.active)
        screen.answer()
        for _ in 0..<5 { screen.lockScreenTask() }
        #expect(screen.automaticAttempts == 1)
    }

    /// After the automatic try, only the button asks, and it never brings an automatic one back.
    @Test func buttonOnlyAfterTheAutomaticTry() {
        var screen = LockScreen()
        screen.lockScreenTask()
        screen.phase(.inactive)
        screen.answer()
        screen.phase(.active)
        for _ in 0..<3 {
            screen.tapFaceID()
            screen.phase(.inactive)
            screen.answer()
            screen.phase(.active)
        }
        #expect(screen.automaticAttempts == 1)
    }

    /// A tap before the automatic try spends it.
    @Test func aTappedPromptSpendsThePresentation() {
        var gate = BiometricAutoPrompt(activationBeginsPresentation: false)
        gate.promptStarted()
        gate.promptEnded(sceneActive: true)
        #expect(!take(&gate))
    }

    /// A lock reported while the app's own prompt is up or leaving (whatever caused it) does not
    /// make a second try due.
    @Test func aLockAroundThePromptDoesNotArm() {
        var screen = LockScreen()
        screen.lockScreenTask()
        screen.phase(.inactive)
        screen.vaultLocked()
        screen.answer()
        screen.vaultLocked()
        screen.phase(.active)
        #expect(screen.automaticAttempts == 1)
    }

    // MARK: - What begins a presentation

    /// A return from the background to a vault that stayed locked asks nothing on its own.
    @Test func returnWithoutALockDoesNotArm() {
        var screen = LockScreen()
        screen.lockScreenTask()
        screen.phase(.inactive)
        screen.answer()
        screen.phase(.active)
        screen.phase(.inactive)
        screen.phase(.background)
        screen.phase(.inactive)
        screen.phase(.active)
        #expect(screen.automaticAttempts == 1)
    }

    /// Auto-lock in the background: the return shows the lock screen with one try.
    @Test func lockInTheBackgroundArmsOnce() {
        var screen = LockScreen()
        _ = screen.gate.takeAutomaticAttempt()
        screen.phase(.inactive)
        screen.phase(.background)
        screen.vaultLocked()
        screen.phase(.inactive)
        screen.phase(.active)
        #expect(screen.automaticAttempts == 1)
        screen.phase(.inactive)
        screen.answer()
        screen.phase(.active)
        #expect(screen.automaticAttempts == 1)
    }

    /// Control Center or a notification over the lock screen is not a lock.
    @Test func controlCenterDoesNotArm() {
        var gate = BiometricAutoPrompt(activationBeginsPresentation: false)
        _ = gate.takeAutomaticAttempt()
        gate.scenePhaseChanged(.inactive)
        gate.scenePhaseChanged(.active)
        #expect(!gate.automaticAttemptDue)
    }

    /// Verrouiller from inside the app: Face ID must not open the vault again by itself.
    @Test func theUsersOwnLockDoesNotArm() {
        var gate = BiometricAutoPrompt(activationBeginsPresentation: false)
        _ = gate.takeAutomaticAttempt()
        gate.userWillLock()
        gate.vaultLocked()
        #expect(!gate.automaticAttemptDue)
        // The next lock (auto-lock later on) is not the user's.
        gate.vaultLocked()
        #expect(gate.automaticAttemptDue)
    }

    @Test func eachRealLockGivesOneTry() {
        var gate = BiometricAutoPrompt(activationBeginsPresentation: false)
        for _ in 0..<3 {
            #expect(take(&gate))
            #expect(!take(&gate))
            gate.vaultLocked()
        }
    }

    // MARK: - Mac

    @Test func macActivationArms() {
        var gate = BiometricAutoPrompt(activationBeginsPresentation: true)
        _ = gate.takeAutomaticAttempt()
        gate.scenePhaseChanged(.inactive)
        gate.scenePhaseChanged(.active)
        #expect(take(&gate))
    }

    /// Even on the Mac, leaving the front during the app's own prompt is not an activation.
    @Test func macPromptInactivityDoesNotArm() {
        var screen = LockScreen(mac: true)
        screen.lockScreenTask()
        screen.phase(.inactive)
        screen.answer()
        screen.phase(.active)
        #expect(screen.automaticAttempts == 1)
    }

    @Test func explicitRequestArms() {
        var gate = BiometricAutoPrompt(activationBeginsPresentation: true)
        _ = gate.takeAutomaticAttempt()
        gate.unlockRequested()
        #expect(take(&gate))
    }

    // MARK: - Mac: Touch ID first

    /// The Mac lock screen asks at once; iPhone, iPad and Vision Pro wait to be seen.
    @Test func macAsksWithoutSettle() {
        #expect(BiometricAutoPrompt(activationBeginsPresentation: true, biometricsFirst: true).settleDelay == .zero)
        #expect(BiometricAutoPrompt(activationBeginsPresentation: false).settleDelay == BiometricAutoPrompt.settle)
    }

    /// Mac: the password column stays hidden while the automatic try is due and while the prompt
    /// is up, and appears once it answers.
    @Test func macHidesThePasswordUntilTouchIDAnswers() {
        var gate = BiometricAutoPrompt(activationBeginsPresentation: true, biometricsFirst: true)
        #expect(!gate.showsPasswordColumn(canUseBiometrics: true, checking: false))
        #expect(take(&gate))
        // Taken, the prompt not raised yet: the lock screen's own check holds the column.
        #expect(!gate.showsPasswordColumn(canUseBiometrics: true, checking: true))
        gate.promptStarted()
        #expect(!gate.showsPasswordColumn(canUseBiometrics: true, checking: false))
        gate.promptEnded(sceneActive: true)
        #expect(gate.showsPasswordColumn(canUseBiometrics: true, checking: false))
    }

    /// The Touch ID button inside the field: the column it belongs to stays.
    @Test func macTappedPromptKeepsThePassword() {
        var gate = BiometricAutoPrompt(activationBeginsPresentation: true, biometricsFirst: true)
        _ = take(&gate)
        gate.promptEnded(sceneActive: true)
        gate.promptStarted(automatic: false)
        #expect(gate.showsPasswordColumn(canUseBiometrics: true, checking: false))
    }

    @Test func passwordColumnWithoutBiometricsOrOffTheMac() {
        let mac = BiometricAutoPrompt(activationBeginsPresentation: true, biometricsFirst: true)
        #expect(mac.showsPasswordColumn(canUseBiometrics: false, checking: false))
        var phone = BiometricAutoPrompt(activationBeginsPresentation: false)
        #expect(phone.showsPasswordColumn(canUseBiometrics: true, checking: false))
        phone.promptStarted()
        #expect(phone.showsPasswordColumn(canUseBiometrics: true, checking: true))
    }

    /// A lock the user asked for has no automatic try: the password column shows at once.
    @Test func macUserLockShowsThePassword() {
        var gate = BiometricAutoPrompt(activationBeginsPresentation: true, biometricsFirst: true)
        _ = take(&gate)
        gate.userWillLock()
        gate.vaultLocked()
        #expect(gate.showsPasswordColumn(canUseBiometrics: true, checking: false))
    }

    @Test func browserUnlockRoute() {
        var gate = BiometricAutoPrompt(activationBeginsPresentation: true, biometricsFirst: true)
        #expect(gate.browserUnlockRoute(appActive: false, canUseBiometrics: true) == .direct)
        #expect(gate.browserUnlockRoute(appActive: true, canUseBiometrics: true) == .window)
        #expect(gate.browserUnlockRoute(appActive: false, canUseBiometrics: false) == .window)
        gate.promptStarted()
        #expect(gate.browserUnlockRoute(appActive: false, canUseBiometrics: true) == .asking)
        let phone = BiometricAutoPrompt(activationBeginsPresentation: false)
        #expect(phone.browserUnlockRoute(appActive: false, canUseBiometrics: true) == .window)
    }

    /// Touch ID asked over the browser and refused: the window that comes forward shows the
    /// password column, with no second automatic try for that request, whatever phases its
    /// return goes through. A later return to the app asks again, as before.
    @Test func directRefusalShowsThePasswordOnce() {
        var gate = BiometricAutoPrompt(activationBeginsPresentation: true, biometricsFirst: true)
        _ = take(&gate)
        gate.scenePhaseChanged(.background)
        gate.promptStarted()
        gate.promptEnded(sceneActive: false)
        gate.directPromptRefused()
        #expect(gate.showsPasswordColumn(canUseBiometrics: true, checking: false))
        gate.scenePhaseChanged(.background)
        gate.scenePhaseChanged(.inactive)
        gate.scenePhaseChanged(.active)
        #expect(!gate.automaticAttemptDue)
        #expect(gate.showsPasswordColumn(canUseBiometrics: true, checking: false))
        gate.scenePhaseChanged(.inactive)
        gate.scenePhaseChanged(.active)
        #expect(take(&gate))
    }

    // MARK: - Privacy shield

    /// The shield stays down for the app's own prompt and while its sheet leaves, so the prompt
    /// rises over the lock screen and its dial.
    @Test func shieldStaysDownForOwnPrompt() {
        var gate = BiometricAutoPrompt(activationBeginsPresentation: false)
        #expect(!gate.shieldVisible(in: .active))
        #expect(gate.shieldVisible(in: .inactive))
        gate.promptStarted()
        gate.scenePhaseChanged(.inactive)
        #expect(!gate.shieldVisible(in: .inactive))
        gate.promptEnded(sceneActive: false)
        #expect(!gate.shieldVisible(in: .inactive))
        gate.scenePhaseChanged(.active)
        #expect(!gate.promptOnScreen)
        // A later inactivity (Control Center) is covered again.
        #expect(gate.shieldVisible(in: .inactive))
    }

    @Test func backgroundAlwaysShields() {
        var gate = BiometricAutoPrompt(activationBeginsPresentation: false)
        gate.promptStarted()
        #expect(gate.shieldVisible(in: .background))
        gate.promptEnded(sceneActive: false)
        gate.scenePhaseChanged(.background)
        #expect(!gate.promptOnScreen)
        #expect(gate.shieldVisible(in: .inactive))
    }

    #if os(iOS)
    /// The worked dial keeps its angle: the door's quarter turn adds to it.
    @Test func workedDialStepsOneTickAtATime() {
        #expect(VaultDial.workAngle(ticks: 0) == 0)
        #expect(VaultDial.workAngle(ticks: 1) == 6)
        #expect(VaultDial.workAngle(ticks: 15) == 90)
    }
    #endif

    private func take(_ gate: inout BiometricAutoPrompt) -> Bool { gate.takeAutomaticAttempt() }
}
