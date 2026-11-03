import SwiftUI
import Testing
@testable import DesignKit

@Suite("Lock screen activation")
struct LockScreenActivationTests {
    /// iPhone: launch, prompt (inactive), cancel (active again): one try only.
    @Test func promptInactivityIsNotANewActivation() {
        var activation = LockScreenActivation(activatesFromInactive: false)
        activation.scenePhaseChanged(.active)
        #expect(take(&activation))
        activation.promptStarted()
        activation.scenePhaseChanged(.inactive)
        activation.promptEnded(sceneActive: false)
        activation.scenePhaseChanged(.active)
        #expect(!take(&activation))
    }

    @Test func returnFromBackgroundArmsAgain() {
        var activation = LockScreenActivation(activatesFromInactive: false)
        activation.scenePhaseChanged(.active)
        #expect(take(&activation))
        activation.scenePhaseChanged(.inactive)
        activation.scenePhaseChanged(.background)
        activation.scenePhaseChanged(.inactive)
        activation.scenePhaseChanged(.active)
        #expect(take(&activation))
        #expect(!take(&activation))
    }

    /// Control Center or a notification over the lock screen is not a return to the app.
    @Test func controlCenterDoesNotArm() {
        var activation = LockScreenActivation(activatesFromInactive: false)
        activation.scenePhaseChanged(.active)
        _ = activation.take()
        activation.scenePhaseChanged(.inactive)
        activation.scenePhaseChanged(.active)
        #expect(!take(&activation))
    }

    @Test func macArmsOnEveryActivation() {
        var activation = LockScreenActivation(activatesFromInactive: true)
        activation.scenePhaseChanged(.active)
        _ = activation.take()
        activation.scenePhaseChanged(.inactive)
        activation.scenePhaseChanged(.active)
        #expect(take(&activation))
    }

    @Test func explicitRequestArms() {
        var activation = LockScreenActivation(activatesFromInactive: false)
        _ = activation.take()
        activation.arm()
        #expect(take(&activation))
    }

    /// The cause of the founder's report: the prompt made the scene inactive and the shield covered
    /// the lock screen. The shield now stays down for the app's own prompt and while its sheet leaves.
    @Test func shieldStaysDownForOwnPrompt() {
        var activation = LockScreenActivation(activatesFromInactive: false)
        activation.scenePhaseChanged(.active)
        #expect(!activation.shieldVisible(in: .active))
        #expect(activation.shieldVisible(in: .inactive))
        activation.promptStarted()
        activation.scenePhaseChanged(.inactive)
        #expect(!activation.shieldVisible(in: .inactive))
        // Success: the session opened while the sheet is still going away.
        activation.promptEnded(sceneActive: false)
        #expect(!activation.shieldVisible(in: .inactive))
        activation.scenePhaseChanged(.active)
        #expect(!activation.promptOnScreen)
        // A later inactivity (Control Center) is covered again.
        #expect(activation.shieldVisible(in: .inactive))
    }

    @Test func backgroundAlwaysShieldsAndEndsThePrompt() {
        var activation = LockScreenActivation(activatesFromInactive: false)
        activation.promptStarted()
        #expect(activation.shieldVisible(in: .background))
        activation.scenePhaseChanged(.background)
        #expect(!activation.promptOnScreen)
        #expect(activation.shieldVisible(in: .inactive))
    }

    @Test func promptAnsweredWhileActiveLeavesNothingBehind() {
        var activation = LockScreenActivation(activatesFromInactive: false)
        activation.scenePhaseChanged(.active)
        activation.promptStarted()
        activation.promptEnded(sceneActive: true)
        #expect(!activation.promptOnScreen)
        #expect(activation.shieldVisible(in: .inactive))
    }

    #if os(iOS)
    /// The worked dial keeps its angle: the door's quarter turn adds to it.
    @Test func workedDialStepsOneTickAtATime() {
        #expect(VaultDial.workAngle(ticks: 0) == 0)
        #expect(VaultDial.workAngle(ticks: 1) == 6)
        #expect(VaultDial.workAngle(ticks: 15) == 90)
    }
    #endif

    private func take(_ activation: inout LockScreenActivation) -> Bool { activation.take() }
}
