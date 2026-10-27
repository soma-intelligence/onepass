// iOS and watchOS only: macOS has no WatchConnectivity and visionOS has no paired watch.
#if canImport(WatchConnectivity) && (os(iOS) || os(watchOS))
import Foundation
import Observation
import WatchConnectivity
import os

/// `CompanionTransport` over `WCSession.default`. Status comes from `isPaired` and
/// `isWatchAppInstalled` on iOS, and is `.ready` on watchOS once the session is activated.
/// Delegate callbacks arrive on a background queue: they are parsed there into `Sendable`
/// values, then handed to the main actor.
@MainActor
@Observable
public final class WatchConnectivityTransport: CompanionTransport {
    public private(set) var status: CompanionStatus
    @ObservationIgnored public var onMessage: ((CompanionMessage) -> Void)?

    @ObservationIgnored private let session: WCSession?
    @ObservationIgnored private var relay: Relay?
    /// `transferUserInfo` before activation is an error: queued messages wait for it here.
    @ObservationIgnored private var pending: [CompanionMessage] = []
    @ObservationIgnored private var activated = false

    public init() {
        session = WCSession.isSupported() ? WCSession.default : nil
        status = session == nil ? .unsupported : .notPaired
    }

    public func activate() {
        guard let session, relay == nil else { return }
        let relay = Relay { [weak self] event in
            Task { @MainActor in self?.handle(event) }
        }
        self.relay = relay
        session.delegate = relay
        session.activate()
    }

    public func sendLatest(_ m: CompanionMessage) throws {
        guard let session, activated else { throw WatchConnectivityTransportError.notActivated }
        try session.updateApplicationContext(m.dictionary)
    }

    public func sendQueued(_ m: CompanionMessage) {
        guard let session, activated else {
            pending.append(m)
            return
        }
        session.transferUserInfo(m.dictionary)
    }

    private func handle(_ event: Relay.Event) {
        switch event {
        case .status(let newStatus, let isActivated):
            status = newStatus
            activated = isActivated
            if isActivated, let session, !pending.isEmpty {
                let queued = pending
                pending = []
                for message in queued { session.transferUserInfo(message.dictionary) }
            }
        case .message(let message):
            onMessage?(message)
        }
    }
}

public enum WatchConnectivityTransportError: Error {
    case notActivated
}

/// The `WCSessionDelegate`: stateless, it only forwards events through `emit`.
private final class Relay: NSObject, WCSessionDelegate, Sendable {
    enum Event: Sendable {
        case status(CompanionStatus, activated: Bool)
        case message(CompanionMessage)
    }

    private let emit: @Sendable (Event) -> Void
    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "companion")

    init(emit: @escaping @Sendable (Event) -> Void) {
        self.emit = emit
    }

    private static func status(of session: WCSession) -> CompanionStatus {
        guard session.activationState == .activated else { return .notPaired }
        #if os(iOS)
        if !session.isPaired { return .notPaired }
        if !session.isWatchAppInstalled { return .appNotInstalled }
        #endif
        return .ready
    }

    private func emitStatus(_ session: WCSession) {
        emit(.status(Self.status(of: session), activated: session.activationState == .activated))
    }

    private func receive(_ dictionary: [String: Any]) {
        if let message = CompanionMessage(dictionary: dictionary) {
            emit(.message(message))
        } else {
            Self.log.error("unknown companion message ignored")
        }
    }

    func session(
        _ session: WCSession, activationDidCompleteWith activationState: WCSessionActivationState, error: (any Error)?
    ) {
        if error != nil { Self.log.error("watch session activation failed") }
        emitStatus(session)
    }

    func session(_ session: WCSession, didReceiveApplicationContext applicationContext: [String: Any]) {
        receive(applicationContext)
    }

    func session(_ session: WCSession, didReceiveUserInfo userInfo: [String: Any] = [:]) {
        receive(userInfo)
    }

    #if os(iOS)
    func sessionDidBecomeInactive(_ session: WCSession) {
        emitStatus(session)
    }

    func sessionDidDeactivate(_ session: WCSession) {
        // The user switched to another watch: activate again for the new one.
        emitStatus(session)
        session.activate()
    }

    func sessionWatchStateDidChange(_ session: WCSession) {
        emitStatus(session)
    }
    #endif
}
#endif
