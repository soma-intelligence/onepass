import Foundation
import Testing

@testable import SafariRelay

/// The relay against the real development host (`cargo build -p
/// onepass-native-host` first; skipped when the binary is missing). Checks the
/// launch arguments: the Safari extension id is the one the host compares to
/// `allowed_extensions`.
struct NativeHostTests {
    static let binary: URL = {
        if let p = ProcessInfo.processInfo.environment["ONEPASS_NATIVE_HOST_BIN"] {
            return URL(fileURLWithPath: p)
        }
        // Tests/SafariRelayTests -> SafariRelay -> SafariExtension -> apple -> repo root.
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        return url.appendingPathComponent("core/target/debug/onepass-native-host")
    }()

    static var available: Bool { FileManager.default.isExecutableFile(atPath: binary.path) }

    /// The first frame the host answers to a session `hello` for a pairing it
    /// does not know, when started for `extensionId`.
    func firstReply(extensionId: String) throws -> [String: Any] {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("onepass-relay-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let config = dir.appendingPathComponent("native-host.json")
        let json: [String: Any] = [
            "data_dir": dir.path,
            "allowed_extensions": ["me.somalabs.onepass.safari"],
            "source": ["kind": "dev"],
            "approval": "auto",
        ]
        try JSONSerialization.data(withJSONObject: json).write(to: config)
        let launcher = ProcessHostLauncher(
            executable: Self.binary,
            arguments: BridgeHost.arguments(config: config, bundlePath: "/Applications/OnePass.app", extensionId: extensionId))
        let hub = RelayHub(launcher: launcher, pollTimeout: 20)
        let conn = String(repeating: "ab", count: 16)
        #expect(hub.handle(RelayRequest(conn: conn, op: .open)) == .ok(frames: [], closed: false))
        let b64 = { (n: Int) in Data(repeating: 7, count: n).base64EncodedString() }
        let hello = #"{"v":1,"t":"hello","pairing_id":"\#(b64(16))","pk":"\#(b64(1600))","n":"\#(b64(32))"}"#
        #expect(hub.handle(RelayRequest(conn: conn, op: .send(frame: Data(hello.utf8)))) == .ok(frames: [], closed: false))
        var frames: [String] = []
        for _ in 0..<3 where frames.isEmpty {
            guard case .ok(let f, _) = hub.handle(RelayRequest(conn: conn, op: .poll)) else { break }
            frames += f
        }
        _ = hub.handle(RelayRequest(conn: conn, op: .close))
        let first = try #require(frames.first)
        return try #require(JSONSerialization.jsonObject(with: Data(first.utf8)) as? [String: Any])
    }

    @Test(.enabled(if: NativeHostTests.available)) func allowedSafariIdReachesTheBridge() throws {
        let reply = try firstReply(extensionId: "me.somalabs.onepass.safari")
        // Past the caller check, into the bridge: the pairing is unknown.
        #expect(reply["t"] as? String == "error")
        #expect(reply["code"] as? String == "unknown_pairing")
    }

    @Test(.enabled(if: NativeHostTests.available)) func otherIdIsRefused() throws {
        let reply = try firstReply(extensionId: "com.example.other")
        #expect(reply["t"] as? String == "error")
        #expect(reply["code"] as? String == "not_allowed")
    }
}
