import Foundation
import Testing
@testable import DesignBridgeKit

private struct Unreadable: Error {}

private struct Described: LocalizedError {
    var errorDescription: String? { "The server is busy." }
    var recoverySuggestion: String? { "Try again in a minute." }
}

@Suite("Loadable state machine (UX-STATE-01)")
struct LoadableTests {
    @Test func startsAsSkeleton() {
        let state = DBLoadable<[Int]>.initial
        #expect(state.phase == .skeleton)
        #expect(state.isLoading)
        #expect(state.value == nil)
    }

    @Test func emptyCollectionBecomesEmpty() {
        var state = DBLoadable<[Int]>.initial
        state.succeed([])
        #expect(state == .empty)
        #expect(state.phase == .empty)
    }

    @Test func valuesBecomeContent() {
        var state = DBLoadable<[Int]>.initial
        state.succeed([1, 2])
        #expect(state == .content([1, 2]))
        #expect(state.value == [1, 2])
    }

    @Test func explicitIsEmptyForNonCollections() {
        var state = DBLoadable<Int>.initial
        state.succeed(0, isEmpty: true)
        #expect(state.phase == .empty)
        state.succeed(3, isEmpty: false)
        #expect(state == .content(3))
    }

    @Test func reloadKeepsContentOnScreen() {
        var state = DBLoadable<[Int]>.content([1])
        state.beginLoading()
        #expect(state == .loading(previous: [1]))
        #expect(state.phase == .refreshing)
        #expect(state.value == [1])
    }

    @Test func failureWithoutContentShowsErrorView() {
        var state = DBLoadable<[Int]>.initial
        state.fail(Unreadable())
        #expect(state.phase == .failed)
        #expect(state.error == .generic)
    }

    @Test func failureOverContentKeepsContent() {
        var state = DBLoadable<[Int]>.content([1])
        state.beginLoading()
        state.fail(Unreadable())
        #expect(state.phase == .failedOverContent)
        #expect(state.value == [1])
        #expect(state.error != nil)
    }

    @Test func retryAfterFailureKeepsPreviousContent() {
        var state = DBLoadable<[Int]>.failed(.generic, previous: [1])
        state.beginLoading()
        #expect(state == .loading(previous: [1]))
    }

    @Test func cancellationRestoresContentSilently() {
        var state = DBLoadable<[Int]>.content([1])
        state.beginLoading()
        state.fail(CancellationError())
        #expect(state == .content([1]))
        #expect(state.error == nil)
    }

    @Test func cancelledURLRequestIsNotAnError() {
        var state = DBLoadable<[Int]>.initial
        state.fail(URLError(.cancelled))
        #expect(state.phase == .skeleton)
    }

    @Test func offlineErrorsGetOfflineCopy() {
        #expect(DBLoadError(URLError(.notConnectedToInternet)) == .offline)
        #expect(DBLoadError(URLError(.networkConnectionLost)) == .offline)
    }

    @Test func localizedErrorsKeepTheirCopy() {
        let error = DBLoadError(Described())
        #expect(error.message == "The server is busy. Try again in a minute.")
    }

    @Test func loadErrorPassesThrough() {
        let custom = DBLoadError(title: "Locked", message: "Unlock to continue.")
        #expect(DBLoadError(custom) == custom)
    }

    @Test func copyNeverSaysSomethingWentWrong() {
        for error in [DBLoadError.generic, .offline] {
            #expect(!error.message.localizedCaseInsensitiveContains("something went wrong"))
            #expect(!error.title.isEmpty)
        }
    }

    @Test func spinnerDelayIs400Milliseconds() {
        #expect(DBStates.spinnerDelay == .milliseconds(400))
    }

    @Test func shimmerStaysSubtle() {
        #expect(DBStates.shimmerOpacity.lowerBound >= 0.4)
        #expect(DBStates.shimmerOpacity.upperBound <= 0.7)
        #expect((1.2...1.5).contains(DBStates.shimmerCycle))
    }
}
