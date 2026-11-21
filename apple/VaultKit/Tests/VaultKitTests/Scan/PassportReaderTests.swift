import CryptoKit
import Foundation
import OnePassCore
import Synchronization
import Testing

@testable import VaultKit

/// The replay fixture of the core (core/onepass-core/tests/fixtures/icao/session_pace.json): a PACE
/// read of a synthetic passport (ICAO specimen, made-up portrait, throwaway CSCA), recorded from the
/// core's FakeChip with fixed randoms. Its own test master list is in it, never the BSI file.
struct SessionFixture: Decodable {
    struct Exchange: Decodable {
        let command: String
        let response: String
    }

    struct Random: Decodable {
        let bacRndIfd: String
        let bacKIfd: String
        let paceMapSk: String
        let paceEphSk: String

        enum CodingKeys: String, CodingKey {
            case bacRndIfd = "bac_rnd_ifd", bacKIfd = "bac_k_ifd"
            case paceMapSk = "pace_map_sk", paceEphSk = "pace_eph_sk"
        }
    }

    let mrz: [String]
    let today: String
    let random: Random
    let masterListHex: String
    let exchange: [Exchange]

    enum CodingKeys: String, CodingKey {
        case mrz, today, random, exchange
        case masterListHex = "master_list"
    }

    static func load() throws -> SessionFixture {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        url.appendPathComponent("core/onepass-core/tests/fixtures/icao/session_pace.json")
        return try JSONDecoder().decode(SessionFixture.self, from: Data(contentsOf: url))
    }

    var masterList: Data { Data(hex: masterListHex) }

    /// A session with the fixture's randoms and date: its commands are the recorded ones, byte for
    /// byte (test XCFramework only, `scan-test-rng`).
    func makeSession(_ lines: [String], _ masterList: Data) throws -> FfiIcaoSession {
        try FfiIcaoSession.newReplayable(
            mrzLines: lines, masterList: masterList, today: today,
            random: FfiIcaoTestRandom(
                bacRndIfd: Data(hex: random.bacRndIfd), bacKIfd: Data(hex: random.bacKIfd),
                paceMapSk: Data(hex: random.paceMapSk), paceEphSk: Data(hex: random.paceEphSk)))
    }
}

extension Data {
    init(hex: String) {
        var bytes = [UInt8]()
        var it = hex.makeIterator()
        while let a = it.next(), let b = it.next() {
            bytes.append(UInt8(String([a, b]), radix: 16) ?? 0)
        }
        self.init(bytes)
    }
}

/// Answers with the recorded responses in order and checks each command byte for byte. `dropAt`:
/// the exchange (0-based) at which the tag is lost once; the next session starts over from the
/// first exchange, as a new tag connection would.
final class ReplayTransport: APDUTransport {
    private struct State {
        var cursor = 0
        var dropAt: Int?
        var mismatches = 0
        var sent = 0
    }

    private let exchange: [SessionFixture.Exchange]
    private let state: Mutex<State>

    init(_ exchange: [SessionFixture.Exchange], dropAt: Int? = nil) {
        self.exchange = exchange
        state = Mutex(State(dropAt: dropAt))
    }

    var mismatches: Int { state.withLock { $0.mismatches } }
    var sent: Int { state.withLock { $0.sent } }

    func send(_ apdu: Data) async throws -> Data {
        try state.withLock { s in
            s.sent += 1
            if s.cursor == s.dropAt {
                s.dropAt = nil
                s.cursor = 0
                throw PassportReadError.lostContact
            }
            guard s.cursor < exchange.count else { throw PassportReadError.lostContact }
            let e = exchange[s.cursor]
            if apdu != Data(hex: e.command) { s.mismatches += 1 }
            s.cursor += 1
            return Data(hex: e.response)
        }
    }
}

/// A chip without EF.CardAccess that refuses BAC (6300): wrong MRZ data.
struct RefusingChip: APDUTransport {
    func send(_ apdu: Data) async throws -> Data {
        let b = [UInt8](apdu)
        switch (b[1], b[2]) {
        case (0xA4, 0x04): return Data([0x90, 0x00])
        case (0xA4, _): return Data([0x6A, 0x82])
        case (0x84, _): return Data([1, 2, 3, 4, 5, 6, 7, 8, 0x90, 0x00])
        default: return Data([0x63, 0x00])
        }
    }
}

/// Loses the tag on every command.
struct LostChip: APDUTransport {
    func send(_ apdu: Data) async throws -> Data { throw PassportReadError.lostContact }
}

/// Answers like the replay, but cancels the reading task during its first exchange: the reader must
/// stop at the next turn of its loop instead of sending the rest.
final class CancellingTransport: APDUTransport {
    private let inner: ReplayTransport

    init(_ exchange: [SessionFixture.Exchange]) {
        inner = ReplayTransport(exchange)
    }

    var sent: Int { inner.sent }

    func send(_ apdu: Data) async throws -> Data {
        let answer = try await inner.send(apdu)
        withUnsafeCurrentTask { $0?.cancel() }
        return answer
    }
}

final class ProgressLog: Sendable {
    private let values = Mutex<[Double]>([])
    func add(_ v: Double) { values.withLock { $0.append(v) } }
    var all: [Double] { values.withLock { $0 } }
}

@Suite struct PassportReaderTests {
    @Test func readsFakePassport() async throws {
        let fixture = try SessionFixture.load()
        let transport = ReplayTransport(fixture.exchange)
        let reader = PassportReader(
            transport: transport, masterList: fixture.masterList, makeSession: fixture.makeSession)
        let progress = ProgressLog()
        let read = try await reader.read(mrz: fixture.mrz) { progress.add($0) }
        #expect(read.status == .verified)
        #expect(read.portraitFormat == .jpeg)
        #expect(read.portrait?.prefix(2) == Data([0xFF, 0xD8]))
        #expect(read.mrz.documentNumber == "L898902C3")
        #expect(transport.mismatches == 0)
        #expect(transport.sent == fixture.exchange.count)
        #expect(progress.all.last == 1.0)
    }

    @Test func retriesOnceOnLostContact() async throws {
        let fixture = try SessionFixture.load()
        let transport = ReplayTransport(fixture.exchange, dropAt: 12)
        let reader = PassportReader(
            transport: transport, masterList: fixture.masterList, makeSession: fixture.makeSession)
        let read = try await reader.read(mrz: fixture.mrz) { _ in }
        #expect(read.status == .verified)
        #expect(transport.mismatches == 0)
        #expect(transport.sent == 12 + 1 + fixture.exchange.count)
    }

    @Test func lostContactTwiceSurfaces() async throws {
        let fixture = try SessionFixture.load()
        let reader = PassportReader(transport: LostChip(), masterList: fixture.masterList)
        await #expect(throws: PassportReadError.lostContact) {
            try await reader.read(mrz: fixture.mrz) { _ in }
        }
    }

    /// Leaving the scan screen cancels the task: the read stops after the exchange in flight.
    @Test func cancelledReadStopsSending() async throws {
        let fixture = try SessionFixture.load()
        let transport = CancellingTransport(fixture.exchange)
        let reader = PassportReader(
            transport: transport, masterList: fixture.masterList, makeSession: fixture.makeSession)
        let task = Task { try await reader.read(mrz: fixture.mrz) { _ in } }
        await #expect(throws: PassportReadError.cancelled) { try await task.value }
        #expect(transport.sent == 1)
    }

    /// A cancelled task never starts a read: no APDU at all.
    @Test func readOfACancelledTaskSendsNothing() async throws {
        let fixture = try SessionFixture.load()
        let transport = ReplayTransport(fixture.exchange)
        let reader = PassportReader(
            transport: transport, masterList: fixture.masterList, makeSession: fixture.makeSession)
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await reader.read(mrz: fixture.mrz) { _ in }
        }
        await #expect(throws: PassportReadError.cancelled) { try await task.value }
        #expect(transport.sent == 0)
    }

    @Test func accessDeniedSurfaces() async throws {
        let fixture = try SessionFixture.load()
        let reader = PassportReader(transport: RefusingChip(), masterList: fixture.masterList)
        await #expect(throws: PassportReadError.accessDenied) {
            try await reader.read(mrz: fixture.mrz) { _ in }
        }
    }

    /// The app's path: a master list pinned by its SHA-256 instead of its signature.
    @Test func pinnedMasterListOpensASession() async throws {
        let fixture = try SessionFixture.load()
        let pin = Data(SHA256.hash(data: fixture.masterList))
        let reader = PassportReader(
            transport: RefusingChip(), masterList: fixture.masterList, masterListSHA256: pin)
        // The session was built: the chip itself refuses the keys.
        await #expect(throws: PassportReadError.accessDenied) {
            try await reader.read(mrz: fixture.mrz) { _ in }
        }
    }

    @Test func pinnedMasterListWithAnotherDigestIsRefused() async throws {
        let fixture = try SessionFixture.load()
        var pin = Data(SHA256.hash(data: fixture.masterList))
        pin[0] ^= 1
        let transport = ReplayTransport(fixture.exchange)
        let reader = PassportReader(
            transport: transport, masterList: fixture.masterList, masterListSHA256: pin)
        await #expect(throws: PassportReadError.unsupported) {
            try await reader.read(mrz: fixture.mrz) { _ in }
        }
        #expect(transport.sent == 0)
    }
}
