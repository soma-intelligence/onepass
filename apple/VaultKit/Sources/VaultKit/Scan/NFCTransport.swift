import Foundation

/// The Core NFC reader errors a passport read tells apart, kept outside Core NFC so the mapping to
/// `PassportReadError` is tested on every platform (`NFCTransport` converts `NFCReaderError.Code`).
enum NFCFailure: Sendable, Equatable {
    case userCanceled
    case unsupportedFeature
    case securityViolation
    case sessionTimeout
    /// The command was refused before it reached the chip (`readerErrorInvalidParameter`): an APDU
    /// Core NFC cannot carry, nothing a second try fixes.
    case invalidParameter
    /// `readerErrorInvalidParameterLength`: same, for a command or answer length Core NFC refuses.
    case invalidParameterLength
    /// The tag went away (connection lost, not connected, retries exceeded) while the session
    /// runs: polling again finds it, so the read starts over.
    case tagLost
    /// Anything else (the session invalidated above all): final.
    case other

    /// A read stopped by this starts over once (`PassportTagLost`).
    var startsReadOver: Bool { self == .tagLost }

    /// `connected`: a tag was connected during this session.
    func readError(connected: Bool) -> PassportReadError {
        switch self {
        case .userCanceled: .cancelled
        case .unsupportedFeature, .securityViolation: .nfcUnavailable
        case .sessionTimeout: connected ? .lostContact : .noChip
        case .invalidParameter, .invalidParameterLength: .unsupported
        case .tagLost, .other: .lostContact
        }
    }
}

#if canImport(CoreNFC) && os(iOS)
    import CoreNFC
    import OSLog

    /// The connected tag, handed from Core NFC's queue to the reader's task. Core NFC serialises
    /// the calls on the tag itself; only one read runs at a time.
    struct ConnectedTag: @unchecked Sendable {
        let tag: any NFCISO7816Tag
    }

    /// Core NFC as an `APDUTransport`: opens the system sheet (`NFCTagReaderSession`, ISO 14443),
    /// keeps the first ISO 7816 tag and sends each APDU with `sendCommand(apdu:)`. A lost tag is
    /// `PassportTagLost` and polling starts again, so the next `send` waits for the tag to come
    /// back; any other failure (the session timed out or ended) is a final `PassportReadError`. A read cancelled while it waits for the tag closes the sheet. Thin on
    /// purpose: the waiting (`TagGate`) and the error mapping (`NFCFailure`) are tested apart, the
    /// rest needs a device. Logs steps only.
    public final class NFCTransport: NSObject, APDUTransport, @unchecked Sendable {
        private static let log = Logger(subsystem: "me.somalabs.onepass", category: "scan")

        private let queue = DispatchQueue(label: "me.somalabs.onepass.nfc")
        private let lock = NSLock()
        // Guarded by `lock`.
        private var session: NFCTagReaderSession?
        private var everConnected = false
        /// The connected tag, and the reads waiting for one.
        private let gate = TagGate<ConnectedTag>()

        /// The device reads NFC tags.
        public static var isAvailable: Bool { NFCTagReaderSession.readingAvailable }

        /// Opens the system sheet with this message.
        public init(alertMessage: String) throws(PassportReadError) {
            super.init()
            guard NFCTagReaderSession.readingAvailable,
                let session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self, queue: queue)
            else { throw .nfcUnavailable }
            session.alertMessage = alertMessage
            lock.withLock { self.session = session }
            session.begin()
            Self.log.info("scan: NFC session opened")
        }

        /// The text of the system sheet (the read's progress).
        public func setAlertMessage(_ message: String) {
            lock.withLock { session }?.alertMessage = message
        }

        /// Closes the sheet: with an error message, or as a success without one.
        public func invalidate(errorMessage: String? = nil) {
            let session = lock.withLock { () -> NFCTagReaderSession? in
                defer { self.session = nil }
                return self.session
            }
            if let errorMessage {
                session?.invalidate(errorMessage: errorMessage)
            } else {
                session?.invalidate()
            }
        }

        public func send(_ apdu: Data) async throws -> Data {
            let tag = try await connectedTag().tag
            guard let command = NFCISO7816APDU(data: apdu) else { throw PassportReadError.unsupported }
            do {
                return try await withCheckedThrowingContinuation { cont in
                    tag.sendCommand(apdu: command) { data, sw1, sw2, error in
                        if let error {
                            cont.resume(throwing: error)
                        } else {
                            cont.resume(returning: data + Data([sw1, sw2]))
                        }
                    }
                }
            } catch {
                if let nfc = error as? NFCReaderError, NFCFailure(nfc.code).startsReadOver {
                    dropTag()
                    throw PassportTagLost()
                }
                throw Self.map(error, connected: true)
            }
        }

        /// The tag, once connected. A cancelled read stops waiting and closes the system sheet.
        private func connectedTag() async throws -> ConnectedTag {
            try await gate.wait { [weak self] in
                Self.log.info("scan: read cancelled while waiting for the tag")
                self?.invalidate()
            }
        }

        private func dropTag() {
            gate.drop()
            let session = lock.withLock { self.session }
            Self.log.info("scan: tag lost, polling again")
            session?.restartPolling()
        }

        static func map(_ error: any Error, connected: Bool) -> PassportReadError {
            if let e = error as? PassportReadError { return e }
            if error is CancellationError { return .cancelled }
            guard let nfc = error as? NFCReaderError else { return .lostContact }
            return NFCFailure(nfc.code).readError(connected: connected)
        }
    }

    extension NFCFailure {
        init(_ code: NFCReaderError.Code) {
            switch code {
            case .readerSessionInvalidationErrorUserCanceled: self = .userCanceled
            case .readerErrorUnsupportedFeature: self = .unsupportedFeature
            case .readerErrorSecurityViolation: self = .securityViolation
            case .readerSessionInvalidationErrorSessionTimeout: self = .sessionTimeout
            case .readerErrorInvalidParameter: self = .invalidParameter
            case .readerErrorInvalidParameterLength: self = .invalidParameterLength
            case .readerTransceiveErrorTagConnectionLost, .readerTransceiveErrorTagNotConnected,
                .readerTransceiveErrorRetryExceeded:
                self = .tagLost
            default: self = .other
            }
        }
    }

    extension NFCTransport: NFCTagReaderSessionDelegate {
        public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {}

        public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: any Error) {
            let mapped = lock.withLock { () -> PassportReadError in
                self.session = nil
                return Self.map(error, connected: everConnected)
            }
            Self.log.info("scan: NFC session ended")
            gate.end(mapped)
        }

        public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
            guard let found = tags.first(where: { if case .iso7816 = $0 { true } else { false } }),
                case .iso7816(let iso) = found
            else {
                session.restartPolling()
                return
            }
            let connected = ConnectedTag(tag: iso)
            session.connect(to: found) { [weak self] error in
                guard let self else { return }
                if error != nil {
                    session.restartPolling()
                    return
                }
                self.lock.withLock { self.everConnected = true }
                Self.log.info("scan: tag connected")
                self.gate.open(connected)
            }
        }
    }
#endif
