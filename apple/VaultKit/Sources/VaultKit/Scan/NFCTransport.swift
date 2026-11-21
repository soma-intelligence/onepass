#if canImport(CoreNFC) && os(iOS)
    import CoreNFC
    import Foundation
    import OSLog

    /// Core NFC as an `APDUTransport`: opens the system sheet (`NFCTagReaderSession`, ISO 14443),
    /// keeps the first ISO 7816 tag and sends each APDU with `sendCommand(apdu:)`. A lost tag is
    /// `PassportReadError.lostContact` and polling starts again, so the next `send` waits for the
    /// tag to come back. Thin on purpose: it cannot be unit tested. Logs steps only.
    /// The connected tag, handed from Core NFC's queue to the reader's task. Core NFC serialises
    /// the calls on the tag itself; only one read runs at a time.
    struct ConnectedTag: @unchecked Sendable {
        let tag: any NFCISO7816Tag
    }

    public final class NFCTransport: NSObject, APDUTransport, @unchecked Sendable {
        private static let log = Logger(subsystem: "me.somalabs.onepass", category: "scan")

        private let queue = DispatchQueue(label: "me.somalabs.onepass.nfc")
        private let lock = NSLock()
        // Guarded by `lock`.
        private var session: NFCTagReaderSession?
        private var tag: ConnectedTag?
        private var waiters: [CheckedContinuation<ConnectedTag, any Error>] = []
        private var ended: PassportReadError?
        private var everConnected = false

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
                let mapped = Self.map(error, connected: true)
                if mapped == .lostContact { dropTag() }
                throw mapped
            }
        }

        private func connectedTag() async throws -> ConnectedTag {
            try await withCheckedThrowingContinuation { cont in
                let ready: Result<ConnectedTag, PassportReadError>? = lock.withLock {
                    if let tag { return .success(tag) }
                    if let ended { return .failure(ended) }
                    waiters.append(cont)
                    return nil
                }
                switch ready {
                case .success(let tag): cont.resume(returning: tag)
                case .failure(let error): cont.resume(throwing: error)
                case nil: break
                }
            }
        }

        private func dropTag() {
            let session = lock.withLock { () -> NFCTagReaderSession? in
                tag = nil
                return self.session
            }
            Self.log.info("scan: tag lost, polling again")
            session?.restartPolling()
        }

        static func map(_ error: any Error, connected: Bool) -> PassportReadError {
            guard let nfc = error as? NFCReaderError else { return .lostContact }
            switch nfc.code {
            case .readerSessionInvalidationErrorUserCanceled: return .cancelled
            case .readerErrorUnsupportedFeature, .readerErrorSecurityViolation: return .nfcUnavailable
            case .readerSessionInvalidationErrorSessionTimeout: return connected ? .lostContact : .noChip
            default: return .lostContact
            }
        }
    }

    extension NFCTransport: NFCTagReaderSessionDelegate {
        public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {}

        public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: any Error) {
            let (waiting, mapped) = lock.withLock { () -> ([CheckedContinuation<ConnectedTag, any Error>], PassportReadError) in
                let mapped = Self.map(error, connected: everConnected)
                ended = mapped
                tag = nil
                self.session = nil
                defer { waiters.removeAll() }
                return (waiters, mapped)
            }
            Self.log.info("scan: NFC session ended")
            for w in waiting { w.resume(throwing: mapped) }
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
                let waiting = self.lock.withLock { () -> [CheckedContinuation<ConnectedTag, any Error>] in
                    self.tag = connected
                    self.everConnected = true
                    defer { self.waiters.removeAll() }
                    return self.waiters
                }
                Self.log.info("scan: tag connected")
                for w in waiting { w.resume(returning: connected) }
            }
        }
    }
#endif
