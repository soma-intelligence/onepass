import Foundation
import Testing

@testable import SafariRelay

/// Real processes on real pipes: `/bin/cat` echoes every frame back, which
/// exercises both directions of the framing; `/usr/bin/true` exits at once.
struct RelayHubTests {
    static let cat = ProcessHostLauncher(executable: URL(fileURLWithPath: "/bin/cat"), arguments: [])
    static let exits = ProcessHostLauncher(executable: URL(fileURLWithPath: "/usr/bin/true"), arguments: [])

    func id(_ n: Int) -> String { String(format: "%032x", n) }

    func request(_ hub: RelayHub, _ op: String, _ conn: String, frame: String? = nil) -> RelayResponse {
        var m: [String: Any] = ["onepass": 1, "op": op, "conn": conn]
        if let frame { m["frame"] = frame }
        return hub.handle(message: m)
    }

    @Test func echoesFramesInOrder() {
        let hub = RelayHub(launcher: Self.cat, pollTimeout: 5)
        let c = id(1)
        #expect(request(hub, "open", c) == .ok(frames: [], closed: false))
        let a = #"{"v":1,"t":"hello","n_e":"AAAA"}"#
        let b = #"{"v":1,"t":"finish","mac":"é=="}"#
        #expect(request(hub, "send", c, frame: a) == .ok(frames: [], closed: false))
        #expect(request(hub, "send", c, frame: b) == .ok(frames: [], closed: false))
        var got: [String] = []
        for _ in 0..<5 where got.count < 2 {
            guard case .ok(let frames, false) = request(hub, "poll", c) else {
                Issue.record("poll failed")
                break
            }
            got += frames
        }
        #expect(got == [a, b])
        #expect(request(hub, "close", c) == .ok(frames: [], closed: true))
        #expect(request(hub, "poll", c) == .failure(.unknownConn))
        #expect(hub.openConnections == 0)
    }

    @Test func pollTimesOutEmpty() {
        let hub = RelayHub(launcher: Self.cat, pollTimeout: 0.2)
        let c = id(2)
        _ = request(hub, "open", c)
        #expect(request(hub, "poll", c) == .ok(frames: [], closed: false))
        _ = request(hub, "close", c)
    }

    @Test func hostExitClosesConnection() {
        let hub = RelayHub(launcher: Self.exits, pollTimeout: 5)
        let c = id(3)
        #expect(request(hub, "open", c) == .ok(frames: [], closed: false))
        #expect(request(hub, "poll", c) == .ok(frames: [], closed: true))
        #expect(hub.openConnections == 0)
        #expect(request(hub, "send", c, frame: "{}") == .failure(.unknownConn))
    }

    @Test func noHostInThisBuild() {
        let hub = RelayHub(launcher: nil)
        #expect(request(hub, "open", id(4)) == .failure(.unavailable))
        #expect(request(hub, "send", id(4), frame: "{}") == .failure(.unknownConn))
    }

    @Test func malformedAndDuplicate() {
        let hub = RelayHub(launcher: Self.cat, pollTimeout: 0.2)
        #expect(hub.handle(message: ["op": "open"]) == .failure(.badRequest))
        let c = id(5)
        _ = request(hub, "open", c)
        #expect(request(hub, "open", c) == .failure(.exists))
        _ = request(hub, "close", c)
    }

    @Test func secondPollIsBusy() async {
        let hub = RelayHub(launcher: Self.cat, pollTimeout: 1)
        let c = id(6)
        _ = request(hub, "open", c)
        async let first = Task.detached { self.request(hub, "poll", c) }.value
        try? await Task.sleep(for: .milliseconds(200))
        #expect(request(hub, "poll", c) == .failure(.busy))
        #expect(await first == .ok(frames: [], closed: false))
        _ = request(hub, "close", c)
    }

    @Test func oldestConnectionIsEvicted() {
        let hub = RelayHub(launcher: Self.cat, pollTimeout: 0.2, maxConnections: 2)
        _ = request(hub, "open", id(7))
        _ = request(hub, "open", id(8))
        _ = request(hub, "send", id(7), frame: "{}")  // 8 is now the least recently used
        _ = request(hub, "open", id(9))
        #expect(hub.openConnections == 2)
        #expect(request(hub, "send", id(8), frame: "{}") == .failure(.unknownConn))
        for n in [7, 9] { _ = request(hub, "close", id(n)) }
    }

    @Test func oversizedHostFrameCloses() throws {
        // A host announcing more than 1 MiB is cut off, nothing delivered.
        let script = "printf '\\001\\000\\020\\000'; sleep 5"
        let hub = RelayHub(
            launcher: ProcessHostLauncher(executable: URL(fileURLWithPath: "/bin/sh"), arguments: ["-c", script]),
            pollTimeout: 5)
        let c = id(10)
        _ = request(hub, "open", c)
        #expect(request(hub, "poll", c) == .ok(frames: [], closed: true))
    }
}
