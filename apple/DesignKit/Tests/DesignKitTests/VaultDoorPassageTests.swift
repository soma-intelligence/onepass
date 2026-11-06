import Testing
@testable import DesignKit

@Suite("Vault door passage")
struct VaultDoorPassageTests {
    @Test func unlockTurnsThenPartsThenEnds() {
        var door = VaultDoorPassage()
        door.handle(.unlocked(reduceMotion: false))
        #expect(door.phase == .turning)
        #expect(door.keepsLockOnTop)
        #expect(door.showsVaultUnderneath)
        #expect(door.dialTurn == VaultDoorPassage.turnDegrees)
        #expect(door.vaultScale == VaultDoorPassage.vaultRestScale)

        door.handle(.turnFinished)
        #expect(door.phase == .parting)
        #expect(!door.keepsLockOnTop)
        #expect(door.showsVaultUnderneath)
        #expect(door.vaultScale == 1)

        door.handle(.panelsOpened)
        #expect(door.phase == .idle)
        #expect(!door.isActive)
    }

    @Test func reduceMotionPlaysNothing() {
        var door = VaultDoorPassage()
        door.handle(.unlocked(reduceMotion: true))
        #expect(door.phase == .idle)
        door.handle(.locked(reduceMotion: true))
        #expect(door.phase == .idle)
        #expect(door.dialTurn == 0)
    }

    @Test func lockClosesThenFades() {
        var door = VaultDoorPassage()
        door.handle(.locked(reduceMotion: false))
        #expect(door.phase == .closing)
        #expect(!door.keepsLockOnTop)
        #expect(!door.showsVaultUnderneath)
        door.handle(.panelsClosed)
        #expect(door.phase == .fading)
        door.handle(.fadeFinished)
        #expect(door.phase == .idle)
    }

    @Test func noWindowToCaptureEndsAtOnce() {
        var door = VaultDoorPassage()
        door.handle(.unlocked(reduceMotion: false))
        door.handle(.captureFailed)
        #expect(door.phase == .idle)
    }

    @Test func lockDuringOpeningReplacesIt() {
        var door = VaultDoorPassage()
        door.handle(.unlocked(reduceMotion: false))
        door.handle(.turnFinished)
        door.handle(.locked(reduceMotion: false))
        #expect(door.phase == .closing)
        // The opening panels' late completion does not end the closing.
        door.handle(.panelsOpened)
        #expect(door.phase == .closing)
    }

    @Test func lateEventsAreIgnored() {
        var door = VaultDoorPassage()
        door.handle(.turnFinished)
        door.handle(.panelsOpened)
        door.handle(.panelsClosed)
        door.handle(.fadeFinished)
        #expect(door.phase == .idle)

        door.handle(.unlocked(reduceMotion: false))
        door.handle(.panelsOpened)
        door.handle(.fadeFinished)
        #expect(door.phase == .turning)
    }

    @Test func interruptionStopsAnyPhase() {
        for setup: [VaultDoorPassage.Event] in [
            [.unlocked(reduceMotion: false)],
            [.unlocked(reduceMotion: false), .turnFinished],
            [.locked(reduceMotion: false)],
            [.locked(reduceMotion: false), .panelsClosed],
        ] {
            var door = VaultDoorPassage()
            setup.forEach { door.handle($0) }
            #expect(door.isActive)
            door.handle(.interrupted)
            #expect(door.phase == .idle)
            #expect(door.vaultScale == 1)
        }
    }

    /// An alert raised by the unlock itself (the Face ID offer) waits for the door: shown at once it
    /// is drawn over the lock screen, brings the keyboard back and rides the parting panels.
    @Test func presentationsWaitForTheOpenDoor() {
        var door = VaultDoorPassage()
        #expect(!door.holdsPresentations)
        door.handle(.unlocked(reduceMotion: false))
        #expect(door.holdsPresentations)
        door.handle(.turnFinished)
        #expect(door.holdsPresentations)
        door.handle(.panelsOpened)
        #expect(!door.holdsPresentations)

        // Reduce Motion: the plain crossfade, nothing to wait for.
        door.handle(.unlocked(reduceMotion: true))
        #expect(!door.holdsPresentations)
    }
}
