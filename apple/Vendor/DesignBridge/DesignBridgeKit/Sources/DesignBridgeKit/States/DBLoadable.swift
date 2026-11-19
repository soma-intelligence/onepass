import Foundation

/// User-facing copy for a failure: what happened and how to fix it (UX-STATE-05).
/// Map errors to copy here, in one place, never raw codes.
public struct DBLoadError: Error, Sendable, Equatable {
    public var title: String
    public var message: String

    public init(title: String, message: String) {
        self.title = title
        self.message = message
    }

    /// Builds copy from any error. `LocalizedError` descriptions are used when present.
    public init(_ error: any Error) {
        if let error = error as? DBLoadError {
            self = error
            return
        }
        if let error = error as? URLError, Self.offlineCodes.contains(error.code) {
            self = .offline
            return
        }
        if let error = error as? LocalizedError, let description = error.errorDescription {
            let message = [description, error.recoverySuggestion].compactMap { $0 }.joined(separator: " ")
            self.init(title: DBStrings.couldNotLoad, message: message)
            return
        }
        self = .generic
    }

    public static var offline: DBLoadError {
        DBLoadError(title: DBStrings.offlineTitle, message: DBStrings.offlineMessage)
    }

    public static var generic: DBLoadError {
        DBLoadError(title: DBStrings.couldNotLoad, message: DBStrings.genericMessage)
    }

    private static let offlineCodes: Set<URLError.Code> = [
        .notConnectedToInternet, .networkConnectionLost, .dataNotAllowed, .internationalRoamingOff,
    ]

    /// True for cancellations, which are not failures and never reach the user.
    static func isCancellation(_ error: any Error) -> Bool {
        if error is CancellationError { return true }
        if let error = error as? URLError, error.code == .cancelled { return true }
        return false
    }
}

/// The four states every data view declares (UX-STATE-01).
///
/// ```swift
/// state.beginLoading()
/// do { state.succeed(try await api.items()) } catch { state.fail(error) }
/// ```
///
/// Reloading keeps the previous content on screen (UX-STATE-02, UX-SCROLL-07):
/// `loading` and `failed` carry the last value, so a refresh never blanks it.
public enum DBLoadable<Value> {
    case loading(previous: Value?)
    case empty
    case failed(DBLoadError, previous: Value?)
    case content(Value)

    /// The initial state: loading with nothing to show yet.
    public static var initial: Self { .loading(previous: nil) }

    /// What the view shows for this state.
    public enum Phase: Sendable, Equatable {
        /// First load: skeleton, spinner after 400 ms.
        case skeleton
        /// Reload over existing content.
        case refreshing
        case empty
        /// Failure with nothing to show: full error view with Retry.
        case failed
        /// Failure while content exists: keep the content, toast the error with Retry.
        case failedOverContent
        case content
    }

    public var phase: Phase {
        switch self {
        case .loading(previous: nil): .skeleton
        case .loading: .refreshing
        case .empty: .empty
        case .failed(_, previous: nil): .failed
        case .failed: .failedOverContent
        case .content: .content
        }
    }

    /// The value to show: the content, or the previous one while loading or after a failure.
    public var value: Value? {
        switch self {
        case .content(let value): value
        case .loading(let previous), .failed(_, let previous): previous
        case .empty: nil
        }
    }

    public var isLoading: Bool {
        if case .loading = self { return true }
        return false
    }

    public var error: DBLoadError? {
        if case .failed(let error, _) = self { return error }
        return nil
    }

    /// Starts a load, keeping what is on screen.
    public mutating func beginLoading() {
        self = .loading(previous: value)
    }

    /// Ends a load with a value; `isEmpty` decides between empty and content.
    public mutating func succeed(_ value: Value, isEmpty: Bool) {
        self = isEmpty ? .empty : .content(value)
    }

    /// Ends a load with an error. Cancellation is not an error: the previous
    /// content comes back and nothing is reported.
    public mutating func fail(_ error: any Error) {
        if DBLoadError.isCancellation(error) {
            if case .loading(let previous?) = self {
                self = .content(previous)
            }
            return
        }
        self = .failed(DBLoadError(error), previous: value)
    }
}

public extension DBLoadable where Value: Collection {
    /// Ends a load; an empty collection becomes `.empty`.
    mutating func succeed(_ value: Value) {
        succeed(value, isEmpty: value.isEmpty)
    }
}

extension DBLoadable: Sendable where Value: Sendable {}
extension DBLoadable: Equatable where Value: Equatable {}
