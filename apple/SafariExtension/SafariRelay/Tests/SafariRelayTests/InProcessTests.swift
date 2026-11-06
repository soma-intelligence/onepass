import Foundation
import Synchronization
import Testing

@testable import SafariRelay

/// The iOS path (spec 2026-11-03-ios-safari-autofill): a bridge served in this process over a
/// socket pair, and the vault messages of the unlock sheet.
struct InProcessTests {
    func id(_ n: Int) -> String { String(format: "%032x", n) }

    /// Echoes every frame on its end of a socket pair, like a bridge that answers in order.
    static func echoLauncher() -> InProcessHostLauncher {
        InProcessHostLauncher {
            var fds: [Int32] = [0, 0]
            guard socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0 else { throw RelayError.unavailable }
            let theirs = FileHandle(fileDescriptor: fds[1], closeOnDealloc: true)
            Thread.detachNewThread {
                while let frame = try? Framing.read(from: theirs) {
                    guard (try? theirs.write(contentsOf: Framing.encode(frame))) != nil else { break }
                }
                try? theirs.close()
            }
            return fds[0]
        }
    }

    @Test func inProcessBridgeRelaysFramesBothWays() {
        let hub = RelayHub(launcher: Self.echoLauncher(), pollTimeout: 5)
        let c = id(7)
        let open: [String: Any] = ["onepass": 1, "op": "open", "conn": c]
        #expect(hub.handle(message: open) == .ok(frames: [], closed: false))
        let frame = #"{"v":1,"t":"hello","n_e":"AAAA"}"#
        let send: [String: Any] = ["onepass": 1, "op": "send", "conn": c, "frame": frame]
        #expect(hub.handle(message: send) == .ok(frames: [], closed: false))
        let poll: [String: Any] = ["onepass": 1, "op": "poll", "conn": c]
        #expect(hub.handle(message: poll) == .ok(frames: [frame], closed: false))
        let close: [String: Any] = ["onepass": 1, "op": "close", "conn": c]
        #expect(hub.handle(message: close) == .ok(frames: [], closed: true))
    }

    @Test func failingConnectIsUnavailable() {
        struct Nope: Error {}
        let hub = RelayHub(launcher: InProcessHostLauncher { throw Nope() })
        #expect(hub.handle(message: ["onepass": 1, "op": "open", "conn": id(1)]) == .failure(.unavailable))
    }

    @Test func parsesVaultMessagesStrictly() throws {
        #expect(try RelayRequest.parse(["onepass": 1, "op": "vault_state"]).op == .vaultState)
        #expect(try RelayRequest.parse(["onepass": 1, "op": "unlock_biometric"]).op == .unlockBiometric)
        #expect(
            try RelayRequest.parse(["onepass": 1, "op": "unlock_password", "password": "Café étoile"]).op
                == .unlockPassword(Data("Café étoile".utf8)))
        let bad: [[String: Any]] = [
            ["onepass": 1, "op": "vault_state", "conn": id(1)],
            ["onepass": 1, "op": "unlock_biometric", "password": "x"],
            ["onepass": 1, "op": "unlock_password"],
            ["onepass": 1, "op": "unlock_password", "password": ""],
            ["onepass": 1, "op": "unlock_password", "password": 12],
            ["onepass": 1, "op": "unlock_password", "password": String(repeating: "a", count: 1025)],
            ["onepass": 1, "op": "unlock_password", "password": "x", "frame": "y"],
            ["onepass": 1, "op": "poll", "conn": id(1), "password": "x"],
            ["onepass": 2, "op": "vault_state"],
        ]
        for m in bad {
            #expect(throws: RelayError.badRequest) { try RelayRequest.parse(m) }
        }
    }

    final class Gate: VaultGate {
        let calls = Mutex<[String]>([])
        func state() -> VaultReply {
            calls.withLock { $0.append("state") }
            return VaultReply(locked: true, account: "Camille", biometry: "faceID")
        }
        func unlockBiometric() -> VaultReply {
            calls.withLock { $0.append("bio") }
            return VaultReply(locked: true, biometry: "faceID", failure: .passwordRequired, message: "Mot de passe requis")
        }
        func unlockPassword(_ password: Data) -> VaultReply {
            calls.withLock { $0.append("pw:\(String(decoding: password, as: UTF8.self))") }
            return VaultReply(locked: false, account: "Camille", biometry: "faceID")
        }
    }

    @Test func vaultMessagesReachTheGate() {
        let gate = Gate()
        let hub = RelayHub(launcher: nil, vault: gate)
        let state = hub.handle(message: ["onepass": 1, "op": "vault_state"])
        #expect(state == .vault(VaultReply(locked: true, account: "Camille", biometry: "faceID")))
        let bio = hub.handle(message: ["onepass": 1, "op": "unlock_biometric"])
        guard case .vault(let r) = bio else {
            Issue.record("no vault reply")
            return
        }
        #expect(r.dictionary["error"] as? String == "password_required")
        #expect(r.dictionary["message"] as? String == "Mot de passe requis")
        let pw = hub.handle(message: ["onepass": 1, "op": "unlock_password", "password": "secret"])
        #expect(pw.dictionary["ok"] as? Bool == true)
        #expect((pw.dictionary["vault"] as? [String: Any])?["locked"] as? Bool == false)
        #expect(gate.calls.withLock { $0 } == ["state", "bio", "pw:secret"])
    }

    @Test func vaultMessagesWithoutAGateAreUnavailable() {
        let hub = RelayHub(launcher: nil)
        #expect(hub.handle(message: ["onepass": 1, "op": "vault_state"]) == .failure(.unavailable))
        #expect(hub.handle(message: ["onepass": 1, "op": "unlock_password", "password": "x"]) == .failure(.unavailable))
    }
}
