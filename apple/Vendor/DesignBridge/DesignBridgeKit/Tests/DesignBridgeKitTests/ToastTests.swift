import Foundation
import Testing
@testable import DesignBridgeKit

@Suite("Toast timing (UX-TOAST-02)")
struct ToastTimingTests {
    @Test func successShowsForOnePointEightSeconds() {
        #expect(DBToast.success("Copied").duration == 1.8)
    }

    @Test func successIsClampedToOnePointFiveToTwoSeconds() {
        #expect(DBToastTiming.duration(kind: .success, hasAction: false, requested: 0.5) == 1.5)
        #expect(DBToastTiming.duration(kind: .success, hasAction: false, requested: 9) == 2)
    }

    @Test func undoShowsForFiveSeconds() {
        #expect(DBToast.undo("Deleted") {}.duration == 5)
    }

    @Test func actionToastIsClampedToFourToSixSeconds() {
        #expect(DBToastTiming.duration(kind: .info, hasAction: true, requested: 1) == 4)
        #expect(DBToastTiming.duration(kind: .success, hasAction: true, requested: 30) == 6)
    }

    @Test func errorStaysAtLeastSixSeconds() {
        #expect(DBToast.error("Couldn't save").duration == 6)
        #expect(DBToast.error("Couldn't save", duration: 2).duration == 6)
        #expect(DBToast.error("Couldn't save", duration: 10).duration == 10)
        #expect(DBToast.error("Couldn't save", action: DBToastButton("Retry") {}).duration == 6)
    }

    @Test func infoDefaultsAndClamps() {
        #expect(DBToast.info("Sync paused").duration == 2.5)
        #expect(DBToastTiming.duration(kind: .info, hasAction: false, requested: 60) == 4)
    }

    @Test func everyKindHasAGlyph() {
        for kind in DBToastKind.allCases {
            #expect(!kind.systemImage.isEmpty)
        }
    }
}

@Suite("Toast queue (UX-TOAST-03)")
struct ToastQueueTests {
    @Test func firstToastShowsImmediately() {
        var queue = DBToastQueue()
        queue.enqueue(.success("Copied"), now: 10)
        #expect(queue.current?.message == "Copied")
        #expect(queue.pending.isEmpty)
        #expect(queue.deadline == 11.8)
    }

    @Test func oneToastAtATimeInOrder() {
        var queue = DBToastQueue()
        queue.enqueue(.success("A"), now: 0)
        queue.enqueue(.success("B"), now: 0.1)
        queue.enqueue(.info("C"), now: 0.2)
        #expect(queue.current?.message == "A")
        #expect(queue.pending.map(\.message) == ["B", "C"])

        #expect(queue.advance(now: 1.7) == false)
        #expect(queue.advance(now: 1.8) == true)
        #expect(queue.current?.message == "B")
        // B starts its own timer when it becomes visible.
        #expect(queue.deadline == 3.6)
        queue.advance(now: 3.6)
        #expect(queue.current?.message == "C")
        queue.advance(now: 3.6 + 2.5)
        #expect(queue.current == nil)
        #expect(queue.deadline == nil)
    }

    @Test func duplicateOfVisibleToastRestartsItsTimer() {
        var queue = DBToastQueue()
        queue.enqueue(.success("Copied"), now: 0)
        let id = queue.current?.id
        queue.enqueue(.success("Copied"), now: 1.5)
        #expect(queue.current?.id == id)
        #expect(queue.pending.isEmpty)
        #expect(queue.deadline == 3.3)
    }

    @Test func duplicateOfPendingToastIsDropped() {
        var queue = DBToastQueue()
        queue.enqueue(.success("A"), now: 0)
        queue.enqueue(.info("B"), now: 0)
        queue.enqueue(.info("B"), now: 0)
        #expect(queue.pending.count == 1)
    }

    @Test func errorsWaitAheadOfOtherToasts() {
        var queue = DBToastQueue()
        queue.enqueue(.success("A"), now: 0)
        queue.enqueue(.success("B"), now: 0)
        queue.enqueue(.error("E1"), now: 0)
        queue.enqueue(.error("E2"), now: 0)
        #expect(queue.pending.map(\.message) == ["E1", "E2", "B"])
    }

    @Test func queueIsCappedAndDropsOldestNonError() {
        var queue = DBToastQueue()
        queue.enqueue(.success("A"), now: 0)
        queue.enqueue(.success("B"), now: 0)
        queue.enqueue(.success("C"), now: 0)
        queue.enqueue(.error("E"), now: 0)
        queue.enqueue(.success("D"), now: 0)
        #expect(queue.pending.count == DBToastQueue.maxPending)
        #expect(queue.pending.map(\.message) == ["E", "C", "D"])
    }

    @Test func pauseStopsTheClockAndResumeExtendsIt() {
        var queue = DBToastQueue()
        queue.enqueue(.success("Copied"), now: 0)
        queue.pause(now: 1)
        #expect(queue.isPaused)
        #expect(queue.deadline == nil)
        #expect(queue.advance(now: 100) == false)
        queue.resume(now: 4)
        // 3 s paused: 1.8 + 3.
        #expect(queue.deadline == 4.8)
        #expect(abs((queue.remaining(now: 4) ?? 0) - 0.8) < 0.0001)
    }

    @Test func dismissShowsNextAndClearsPause() {
        var queue = DBToastQueue()
        queue.enqueue(.success("A"), now: 0)
        queue.enqueue(.error("E"), now: 0)
        queue.pause(now: 0.5)
        queue.dismissCurrent(now: 1)
        #expect(queue.current?.message == "E")
        #expect(!queue.isPaused)
        #expect(queue.deadline == 7)
    }

    @Test func pauseWithNothingVisibleIsIgnored() {
        var queue = DBToastQueue()
        queue.pause(now: 0)
        #expect(!queue.isPaused)
    }

    @Test func removeAllClearsEverything() {
        var queue = DBToastQueue()
        queue.enqueue(.success("A"), now: 0)
        queue.enqueue(.success("B"), now: 0)
        queue.removeAll()
        #expect(queue.current == nil)
        #expect(queue.pending.isEmpty)
    }
}

@MainActor
@Suite("Toast center and presenter")
struct ToastCenterTests {
    @Test func showAnnouncesEachNewToastOnce() {
        var announced: [String] = []
        let center = DBToastCenter { announced.append($0.message) }
        center.show(.success("Copied"))
        center.show(.success("Copied"))
        center.show(.error("Failed"))
        #expect(announced == ["Copied"])
        center.dismiss()
        #expect(announced == ["Copied", "Failed"])
        #expect(center.current?.kind == .error)
    }

    @Test func copyToClipboardWritesAndToasts() {
        var written: [String] = []
        var shown: [DBToast] = []
        let presenter = DBToastPresenter(present: { shown.append($0) }, pasteboard: { written.append($0) })
        presenter.copyToClipboard("1234", label: "Code copied")
        #expect(written == ["1234"])
        #expect(shown.count == 1)
        #expect(shown.first?.kind == .success)
        #expect(shown.first?.message == "Code copied")
        #expect(shown.first?.duration == DBToastTiming.success)
    }

    @Test func copyToClipboardDefaultLabel() {
        var shown: [DBToast] = []
        let presenter = DBToastPresenter(present: { shown.append($0) }, pasteboard: { _ in })
        presenter.copyToClipboard("x")
        #expect(shown.first?.message == "Copied")
    }

    @Test func timerExpiresTheToast() async throws {
        let center = DBToastCenter { _ in }
        center.show(DBToast(kind: .success, message: "Quick", duration: 1.5))
        #expect(center.current != nil)
        try await Task.sleep(for: .seconds(1.8))
        #expect(center.current == nil)
    }

    @Test func pausedToastDoesNotExpire() async throws {
        let center = DBToastCenter { _ in }
        center.show(DBToast(kind: .success, message: "Held", duration: 1.5))
        center.pause(.touch)
        try await Task.sleep(for: .seconds(1.8))
        #expect(center.current?.message == "Held")
        center.resume(.touch)
        #expect(center.current?.message == "Held")
    }

    @Test func allPauseReasonsMustClearBeforeResuming() {
        let center = DBToastCenter { _ in }
        center.show(.success("A"))
        center.pause(.touch)
        center.pause(.voiceOver)
        center.resume(.touch)
        #expect(center.queue.isPaused)
        center.resume(.voiceOver)
        #expect(!center.queue.isPaused)
    }
}

@Suite("Retry toast")
struct RetryToastTests {
    @Test func retryIsAnErrorWithARetryButtonThatStaysSixSeconds() {
        let toast = DBToast.retry("Couldn't load. Check your connection.") {}
        #expect(toast.kind == .error)
        #expect(toast.action?.title == DBStrings.retry)
        #expect(toast.duration >= DBToastTiming.errorMinimum)
    }
}

@Suite("Toast placement (UX-TOAST-03)")
struct ToastPlacementTests {
    @Test func defaultSitsBelowTheNavigationBar() {
        #if os(iOS)
        #expect(DBToastPlacement.belowNavigationBar.topInset == DBToastPlacement.navigationBarHeight + DBToastPlacement.gap)
        #else
        #expect(DBToastPlacement.belowNavigationBar.topInset == DBToastPlacement.gap)
        #endif
    }

    @Test func topPlacementKeepsOnlyTheGap() {
        #expect(DBToastPlacement.top.topInset == DBToastPlacement.gap)
    }
}
