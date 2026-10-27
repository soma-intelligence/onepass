import Foundation
import Testing

@testable import SafariRelay

/// An in-memory stream that hands out at most `chunk` bytes per read.
final class Bytes: ByteSource {
    private var data: Data
    private let chunk: Int

    init(_ data: Data, chunk: Int = .max) {
        self.data = data
        self.chunk = chunk
    }

    func read(upTo count: Int) throws -> Data {
        let n = min(count, chunk, data.count)
        let out = data.prefix(n)
        data.removeFirst(n)
        return Data(out)
    }
}

struct FramingTests {
    @Test func roundTripLittleEndianLength() throws {
        let body = Data(#"{"v":1,"t":"hello"}"#.utf8)
        let frame = try Framing.encode(body)
        #expect(frame.prefix(4) == Data([UInt8(body.count), 0, 0, 0]))
        #expect(frame.dropFirst(4) == body)
        // Read back one byte at a time: partial reads are reassembled.
        let src = Bytes(frame + frame, chunk: 1)
        #expect(try Framing.read(from: src) == body)
        #expect(try Framing.read(from: src) == body)
        #expect(try Framing.read(from: src) == nil)
    }

    @Test func emptyStreamIsCleanEnd() throws {
        #expect(try Framing.read(from: Bytes(Data())) == nil)
    }

    @Test func emptyFrame() throws {
        #expect(try Framing.read(from: Bytes(Data([0, 0, 0, 0]))) == Data())
    }

    @Test func maximumLengthIsAccepted() throws {
        let body = Data(repeating: 0x61, count: Framing.maxFrame)
        let frame = try Framing.encode(body)
        #expect(frame.prefix(4) == Data([0, 0, 0x10, 0]))
        #expect(try Framing.read(from: Bytes(frame))?.count == Framing.maxFrame)
    }

    @Test func overCapIsRefusedBothWays() {
        #expect(throws: RelayError.tooLarge) {
            try Framing.encode(Data(count: Framing.maxFrame + 1))
        }
        // 1 MiB + 1 announced: refused without reading a body.
        #expect(throws: RelayError.tooLarge) {
            try Framing.read(from: Bytes(Data([1, 0, 0x10, 0])))
        }
        #expect(throws: RelayError.tooLarge) {
            try Framing.read(from: Bytes(Data([0xff, 0xff, 0xff, 0xff])))
        }
    }

    @Test func truncatedHeaderOrBody() {
        #expect(throws: RelayError.truncated) {
            try Framing.read(from: Bytes(Data([5, 0])))
        }
        #expect(throws: RelayError.truncated) {
            try Framing.read(from: Bytes(Data([5, 0, 0, 0, 0x61, 0x62])))
        }
    }

    @Test func readErrorIsTransport() {
        struct Broken: ByteSource {
            func read(upTo count: Int) throws -> Data { throw CocoaError(.fileReadUnknown) }
        }
        #expect(throws: RelayError.transport) { try Framing.read(from: Broken()) }
    }
}

struct RelayRequestTests {
    let conn = "0123456789abcdef0123456789abcdef"

    @Test func parsesEachOp() throws {
        #expect(try RelayRequest.parse(["onepass": 1, "op": "open", "conn": conn]) == RelayRequest(conn: conn, op: .open))
        #expect(try RelayRequest.parse(["onepass": 1, "op": "poll", "conn": conn]) == RelayRequest(conn: conn, op: .poll))
        #expect(try RelayRequest.parse(["onepass": 1, "op": "close", "conn": conn]) == RelayRequest(conn: conn, op: .close))
        let text = #"{"v":1,"t":"finish","mac":"AA=="}"#
        #expect(
            try RelayRequest.parse(["onepass": 1, "op": "send", "conn": conn, "frame": text])
                == RelayRequest(conn: conn, op: .send(frame: Data(text.utf8))))
    }

    @Test func refusesMalformedRequests() {
        let bad: [Any?] = [
            nil,
            "open",
            [String: Any](),
            ["onepass": 2, "op": "open", "conn": conn],
            ["onepass": true, "op": "open", "conn": conn],
            ["onepass": 1.5, "op": "open", "conn": conn],
            ["onepass": "1", "op": "open", "conn": conn],
            ["onepass": 1, "op": "connect", "conn": conn],
            ["onepass": 1, "op": "open", "conn": "short"],
            ["onepass": 1, "op": "open", "conn": conn.uppercased()],
            ["onepass": 1, "op": "open", "conn": conn + "0"],
            ["onepass": 1, "op": "open", "conn": "0123456789abcdef0123456789abcdeg"],
            ["onepass": 1, "op": "open", "conn": conn, "frame": "{}"],
            ["onepass": 1, "op": "send", "conn": conn],
            ["onepass": 1, "op": "send", "conn": conn, "frame": ["v": 1]],
            ["onepass": 1, "op": "open", "conn": conn, "extra": 1],
        ]
        for m in bad {
            #expect(throws: RelayError.badRequest) { try RelayRequest.parse(m) }
        }
    }

    @Test func refusesOversizedFrame() {
        let big = String(repeating: "a", count: Framing.maxFrame + 1)
        #expect(throws: RelayError.tooLarge) {
            try RelayRequest.parse(["onepass": 1, "op": "send", "conn": conn, "frame": big])
        }
    }

    @Test func responseDictionaries() {
        let ok = RelayResponse.ok(frames: ["{}"], closed: false).dictionary
        #expect(ok["ok"] as? Bool == true)
        #expect(ok["frames"] as? [String] == ["{}"])
        #expect(ok["closed"] as? Bool == false)
        let err = RelayResponse.failure(.unknownConn).dictionary
        #expect(err["ok"] as? Bool == false)
        #expect(err["error"] as? String == "unknown_conn")
        #expect(err.count == 2)
    }
}
