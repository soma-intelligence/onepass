import Foundation
import OSLog
import OnePassCore

// Passport chip reading (NFC documents P1, spec 6.2). The core's FfiIcaoSession decides every
// APDU; the transport only carries bytes. Nothing here logs APDU bytes, keys or identity data:
// steps and sizes only.

/// A pipe to a contactless chip: one command APDU in, the answer (data then SW1 SW2) out.
/// `NFCTransport` on iPhone; a replay of a recorded read in the tests.
public protocol APDUTransport: Sendable {
    func send(_ apdu: Data) async throws -> Data
}

/// Why a passport read stopped.
public enum PassportReadError: Error, Sendable, Equatable {
    /// The chip refused the keys derived from the MRZ: the MRZ was misread or is not this
    /// document's.
    case accessDenied
    /// The phone lost the chip (moved away) twice in a row.
    case lostContact
    /// No chip answered.
    case noChip
    /// This device cannot read NFC tags.
    case nfcUnavailable
    /// The chip offers nothing this reader speaks, or answered in a way the protocol does not
    /// allow (`FfiIcaoFailure.other`).
    case unsupported
    /// The user closed the system sheet.
    case cancelled
}

/// Reads a passport chip through a transport, against a CSCA master list.
public struct PassportReader: Sendable {
    typealias SessionFactory = @Sendable (_ mrz: [String], _ masterList: Data) throws -> FfiIcaoSession

    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "scan")

    private let transport: any APDUTransport
    private let masterList: Data
    private let makeSession: SessionFactory

    public init(transport: any APDUTransport, masterList: Data) {
        self.init(transport: transport, masterList: masterList) { mrz, ml in
            try FfiIcaoSession(mrzLines: mrz, masterList: ml)
        }
    }

    /// A master list the app ships, pinned by its SHA-256 (32 bytes) instead of its signature: the
    /// BSI list's signer chains to a brainpoolP512r1 CSCA the core cannot verify. The app keeps
    /// the digest next to the file (App/Resources/CSCAMasterList.swift).
    public init(transport: any APDUTransport, masterList: Data, masterListSHA256: Data) {
        self.init(transport: transport, masterList: masterList) { mrz, ml in
            try FfiIcaoSession.newPinned(mrzLines: mrz, masterList: ml, masterListSha256: masterListSHA256)
        }
    }

    /// Tests: a session with fixed randoms, so a recorded read replays byte for byte.
    init(transport: any APDUTransport, masterList: Data, makeSession: @escaping SessionFactory) {
        self.transport = transport
        self.masterList = masterList
        self.makeSession = makeSession
    }

    /// Reads the chip of the document whose MRZ lines these are. A lost contact starts the read
    /// over once, with a new session (spec 6.2). `progress` gets 0 to 1.
    public func read(
        mrz: [String], progress: @Sendable (Double) -> Void
    ) async throws(PassportReadError) -> FfiChipRead {
        do {
            return try await readOnce(mrz: mrz, progress: progress)
        } catch .lostContact {
            if Task.isCancelled { throw .cancelled }
            Self.log.info("scan: contact lost, reading again")
            progress(0)
            return try await readOnce(mrz: mrz, progress: progress)
        }
    }

    private func readOnce(
        mrz: [String], progress: @Sendable (Double) -> Void
    ) async throws(PassportReadError) -> FfiChipRead {
        let session: FfiIcaoSession
        do {
            session = try makeSession(mrz, masterList)
        } catch {
            // A MRZ that fails its check digits or a master list that does not load: nothing the
            // chip can fix.
            Self.log.error("scan: session refused its inputs")
            throw .unsupported
        }
        var step = session.start()
        var exchanges = 0
        while true {
            // Leaving the screen cancels the read: no APDU after that.
            if Task.isCancelled {
                Self.log.info("scan: read cancelled after \(exchanges) exchanges")
                throw .cancelled
            }
            switch step {
            case .send(let apdu):
                let answer: Data
                do {
                    answer = try await transport.send(apdu)
                } catch {
                    let mapped = Self.transportError(error)
                    Self.log.info("scan: transport stopped after \(exchanges) exchanges")
                    throw mapped
                }
                exchanges += 1
                Self.log.debug("scan: exchange \(exchanges), \(apdu.count) bytes out, \(answer.count) in")
                step = session.onResponse(bytes: answer)
                progress(Double(session.progress()))
            case .done(let read):
                Self.log.info(
                    "scan: read done in \(exchanges) exchanges, portrait \(read.portrait?.count ?? 0) bytes")
                progress(1)
                return read
            case .failed(let reason):
                Self.log.info("scan: read failed after \(exchanges) exchanges")
                throw Self.failure(reason)
            }
        }
    }

    static func failure(_ reason: FfiIcaoFailure) -> PassportReadError {
        switch reason {
        case .accessDenied: .accessDenied
        case .lostContact: .lostContact
        case .noChip: .noChip
        case .unsupported, .other: .unsupported
        }
    }

    static func transportError(_ error: any Error) -> PassportReadError {
        if let e = error as? PassportReadError { return e }
        if error is CancellationError { return .cancelled }
        return .lostContact
    }
}
