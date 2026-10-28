import Foundation
import Testing

@testable import SafariRelay

/// The socket launcher against a listener in a temporary directory that
/// plays the app: it checks the opening frame, then echoes frames back.
struct AppSocketTests {
    /// A listening socket; `serve` runs on its first connection.
    final class Listener: @unchecked Sendable {
        let path: String
        let fd: Int32
        private(set) var opening: Data?

        init() throws {
            let dir = URL(fileURLWithPath: "/tmp").appendingPathComponent("op-\(UInt32.random(in: 0...UInt32.max))")
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            path = dir.appendingPathComponent("b.sock").path
            fd = socket(AF_UNIX, SOCK_STREAM, 0)
            var addr = sockaddr_un()
            addr.sun_family = sa_family_t(AF_UNIX)
            let bytes = Array(path.utf8)
            withUnsafeMutableBytes(of: &addr.sun_path) { raw in
                for (i, b) in bytes.enumerated() { raw[i] = b }
            }
            let rc = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
                }
            }
            precondition(rc == 0 && listen(fd, 4) == 0)
        }

        /// Accept one client, record its opening frame, echo the rest.
        func echoOnce() {
            Thread.detachNewThread { [self] in
                let c = accept(fd, nil, nil)
                guard c >= 0 else { return }
                let h = FileHandle(fileDescriptor: c, closeOnDealloc: true)
                opening = try? Framing.read(from: h)
                while let f = try? Framing.read(from: h), let out = try? Framing.encode(f) {
                    try? h.write(contentsOf: out)
                }
            }
        }

        deinit {
            close(fd)
            try? FileManager.default.removeItem(atPath: URL(fileURLWithPath: path).deletingLastPathComponent().path)
        }
    }

    func id(_ n: Int) -> String { String(format: "%032x", n) }

    func request(_ hub: RelayHub, _ op: String, _ conn: String, frame: String? = nil) -> RelayResponse {
        var m: [String: Any] = ["onepass": 1, "op": op, "conn": conn]
        if let frame { m["frame"] = frame }
        return hub.handle(message: m)
    }

    @Test func relaysThroughTheAppSocketAfterTheOpeningFrame() throws {
        let l = try Listener()
        l.echoOnce()
        let hub = RelayHub(launcher: AppSocketLauncher(path: l.path) { _ in true }, pollTimeout: 5)
        let c = id(1)
        #expect(request(hub, "open", c) == .ok(frames: [], closed: false))
        let hello = #"{"v":1,"t":"hello"}"#
        #expect(request(hub, "send", c, frame: hello) == .ok(frames: [], closed: false))
        var got: [String] = []
        for _ in 0..<5 where got.isEmpty {
            guard case .ok(let frames, false) = request(hub, "poll", c) else { break }
            got += frames
        }
        #expect(got == [hello])
        #expect(l.opening == AppSocket.opening)
        #expect(request(hub, "close", c) == .ok(frames: [], closed: true))
    }

    @Test func listenerThatIsNotTheAppIsRefused() throws {
        let l = try Listener()
        l.echoOnce()
        let hub = RelayHub(launcher: AppSocketLauncher(path: l.path) { _ in false })
        #expect(request(hub, "open", id(2)) == .failure(.unavailable))
        #expect(hub.openConnections == 0)
    }

    @Test func appNotRunningIsUnavailable() {
        let hub = RelayHub(launcher: AppSocketLauncher(path: "/tmp/op-missing-\(UUID().uuidString).sock") { _ in true })
        #expect(request(hub, "open", id(3)) == .failure(.unavailable))
        let long = "/tmp/" + String(repeating: "a", count: 120)
        let hub2 = RelayHub(launcher: AppSocketLauncher(path: long) { _ in true })
        #expect(request(hub2, "open", id(4)) == .failure(.unavailable))
    }

    @Test func requirementPinsTeamAndIdentifier() {
        #expect(
            AppSocket.requirement(team: "ABCDE12345")
                == #"anchor apple generic and certificate leaf[subject.OU] = "ABCDE12345" and identifier "me.somalabs.onepass""#)
        #expect(AppSocket.requirement(team: "abcde12345") == nil)
        #expect(AppSocket.requirement(team: #"X" or anchor"#) == nil)
    }

    @Test func unsignedTestProcessHasNoTeamAndNoAppSocket() {
        // `swift test` binaries are signed ad hoc: no production bridge.
        #expect(AppSocket.ownTeam() == nil)
        #expect(AppSocket.launcher() == nil)
    }

    @Test func peerCheckFailsOnAPlainPipeAndAnAdHocPeer() throws {
        var fds: [Int32] = [0, 0]
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)
        defer { close(fds[0]); close(fds[1]) }
        // The peer is this ad hoc test process: never the app.
        let req = AppSocket.requirement(team: "ABCDE12345")!
        #expect(AppSocket.checkPeer(fd: fds[0], requirement: req) == .refused)
        #expect(AppSocket.checkPeer(fd: -1, requirement: req) == .refused)
    }

    @Test func onlyASandboxRefusalOfTheLookupIsTolerated() {
        #expect(AppSocket.verdict(lookup: errSecSuccess, validity: errSecSuccess) == .verified)
        #expect(AppSocket.verdict(lookup: errSecSuccess, validity: errSecCSReqFailed) == .refused)
        #expect(AppSocket.verdict(lookup: 100_001, validity: nil) == .lookupDenied)
        #expect(AppSocket.verdict(lookup: errSecCSNoSuchCode, validity: nil) == .refused)
        #expect(AppSocket.verdict(lookup: 100_000 + ESRCH, validity: nil) == .refused)
        #expect(AppSocket.acceptsListener(.verified))
        #expect(AppSocket.acceptsListener(.lookupDenied))
        #expect(!AppSocket.acceptsListener(.refused))
    }
}
