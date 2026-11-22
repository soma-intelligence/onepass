import Foundation
import Synchronization
import Testing

@testable import VaultKit

/// The wait for a chip inside `NFCTransport`, and the Core NFC error mapping, without Core NFC.
@Suite struct TagGateTests {
    final class Flag: Sendable {
        private let value = Mutex(0)
        func hit() { value.withLock { $0 += 1 } }
        var count: Int { value.withLock { $0 } }
    }

    /// Polls `condition` for up to two seconds (the waiter registers on another task).
    private func eventually(_ condition: () -> Bool) async {
        for _ in 0..<200 where !condition() {
            try? await Task.sleep(for: .milliseconds(10))
        }
    }

    @Test func waiterGetsTheTagOnceConnected() async throws {
        let gate = TagGate<Int>()
        let waiter = Task { try await gate.wait() }
        await eventually { gate.waiting == 1 }
        gate.open(7)
        #expect(try await waiter.value == 7)
        // Connected: the next wait returns at once.
        #expect(try await gate.wait() == 7)
    }

    @Test func cancellingAWaiterRemovesItAndClosesTheSession() async throws {
        let gate = TagGate<Int>()
        let closed = Flag()
        let waiter = Task { try await gate.wait { closed.hit() } }
        await eventually { gate.waiting == 1 }
        #expect(gate.waiting == 1)
        waiter.cancel()
        await #expect(throws: PassportReadError.cancelled) { try await waiter.value }
        #expect(gate.waiting == 0)
        #expect(closed.count == 1)
    }

    @Test func aCancelledTaskDoesNotWait() async throws {
        let gate = TagGate<Int>()
        let waiter = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await gate.wait()
        }
        await #expect(throws: PassportReadError.cancelled) { try await waiter.value }
        #expect(gate.waiting == 0)
    }

    @Test func endedSessionFailsWaiters() async throws {
        let gate = TagGate<Int>()
        let waiter = Task { try await gate.wait() }
        await eventually { gate.waiting == 1 }
        gate.end(.noChip)
        await #expect(throws: PassportReadError.noChip) { try await waiter.value }
        await #expect(throws: PassportReadError.noChip) { try await gate.wait() }
    }

    @Test func droppedTagMakesTheNextReadWait() async throws {
        let gate = TagGate<Int>()
        gate.open(1)
        gate.drop()
        let waiter = Task { try await gate.wait() }
        await eventually { gate.waiting == 1 }
        #expect(gate.waiting == 1)
        gate.open(2)
        #expect(try await waiter.value == 2)
    }

    /// Review finding: an invalid parameter is not a lost tag (a retry would fail the same way).
    @Test func invalidParametersAreUnsupported() {
        #expect(NFCFailure.invalidParameter.readError(connected: true) == .unsupported)
        #expect(NFCFailure.invalidParameterLength.readError(connected: true) == .unsupported)
        #expect(NFCFailure.invalidParameter.readError(connected: false) == .unsupported)
    }

    @Test func otherReaderErrorsKeepTheirMapping() {
        #expect(NFCFailure.userCanceled.readError(connected: true) == .cancelled)
        #expect(NFCFailure.unsupportedFeature.readError(connected: false) == .nfcUnavailable)
        #expect(NFCFailure.securityViolation.readError(connected: false) == .nfcUnavailable)
        #expect(NFCFailure.sessionTimeout.readError(connected: false) == .noChip)
        #expect(NFCFailure.sessionTimeout.readError(connected: true) == .lostContact)
        #expect(NFCFailure.other.readError(connected: true) == .lostContact)
        #expect(NFCFailure.tagLost.readError(connected: true) == .lostContact)
    }

    /// Review finding: only a lost tag starts the read over; a session that timed out or ended
    /// cannot read again.
    @Test func onlyALostTagStartsTheReadOver() {
        #expect(NFCFailure.tagLost.startsReadOver)
        for failure: NFCFailure in [
            .userCanceled, .unsupportedFeature, .securityViolation, .sessionTimeout, .invalidParameter,
            .invalidParameterLength, .other,
        ] {
            #expect(!failure.startsReadOver)
        }
    }
}
