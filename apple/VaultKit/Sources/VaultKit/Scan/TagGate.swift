import Foundation

/// Where the reader waits for a chip: `wait` returns the connected value, or suspends until one is
/// `open`ed, the session `end`s, or the waiting task is cancelled. Cancelling a waiting task removes
/// its waiter (the continuation is resumed with `.cancelled`, never leaked) and calls `onCancel`, so
/// the NFC session can close its system sheet. Platform neutral so it can be tested without Core
/// NFC; `NFCTransport` keeps its connected tag here.
final class TagGate<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    // Guarded by `lock`.
    private var value: Value?
    private var ended: PassportReadError?
    private var waiters: [UUID: CheckedContinuation<Value, any Error>] = [:]

    init() {}

    /// Tasks waiting for a value (tests).
    var waiting: Int { lock.withLock { waiters.count } }

    /// The connected value, as soon as there is one. Throws the error the session ended with, or
    /// `.cancelled` when the calling task is cancelled.
    func wait(onCancel: @escaping @Sendable () -> Void = {}) async throws -> Value {
        let id = UUID()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Value, any Error>) in
                // Task cancellation sets the flag before the handler runs: checked under the lock,
                // a waiter is either seen by the handler or never registered.
                let ready: Result<Value, PassportReadError>? = lock.withLock {
                    if Task.isCancelled { return .failure(.cancelled) }
                    if let value { return .success(value) }
                    if let ended { return .failure(ended) }
                    waiters[id] = cont
                    return nil
                }
                switch ready {
                case .success(let value): cont.resume(returning: value)
                case .failure(let error): cont.resume(throwing: error)
                case nil: break
                }
            }
        } onCancel: {
            let cont = lock.withLock { waiters.removeValue(forKey: id) }
            cont?.resume(throwing: PassportReadError.cancelled)
            onCancel()
        }
    }

    /// A chip is connected: every waiter gets it, and later `wait`s return it at once.
    func open(_ newValue: Value) {
        let waiting = lock.withLock { () -> [CheckedContinuation<Value, any Error>] in
            value = newValue
            defer { waiters.removeAll() }
            return Array(waiters.values)
        }
        for w in waiting { w.resume(returning: newValue) }
    }

    /// The chip went away: the next `wait` suspends until another `open`.
    func drop() {
        lock.withLock { value = nil }
    }

    /// The session is over: every waiter, and every later `wait`, fails with `error`.
    func end(_ error: PassportReadError) {
        let waiting = lock.withLock { () -> [CheckedContinuation<Value, any Error>] in
            ended = error
            value = nil
            defer { waiters.removeAll() }
            return Array(waiters.values)
        }
        for w in waiting { w.resume(throwing: error) }
    }
}
