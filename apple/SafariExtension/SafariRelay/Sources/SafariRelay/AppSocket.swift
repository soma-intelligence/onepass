import Foundation
import Security

/// The production path (spec 2026-10-27-release-bridge-design): the Mac app
/// listens on `bridge.sock` at the root of its App Group container
/// (`<team>.me.somalabs.onepass`) and serves the bridge from the vault the
/// user unlocked. The extension connects, sends the opening frame
/// `{"onepass_relay":1}`, then relays envelopes byte for byte. The app checks
/// this extension's code signature (kernel audit token) before reading a byte.
///
/// The extension checks the listener's signature the same way when the system
/// lets it. Inside an app bundle the App Sandbox refuses that lookup with EPERM
/// (measured 2026-10-27, spec P-02): the extension then relies on the App
/// Group container (only this team's processes, or ones the user lets read
/// other apps' data, can create the socket) and on the bridge protocol (a
/// session needs the pairing key; a pairing needs the code the user compares
/// with the app's Touch ID sheet). A listener positively identified as anything
/// else is refused.
public enum AppSocket {
    public static let appIdentifier = "me.somalabs.onepass"
    public static let groupSuffix = "me.somalabs.onepass"
    public static let socketName = "bridge.sock"
    /// The opening frame of the Safari extension (no extension id: the app
    /// knows it from the code signature).
    public static let opening = Data(#"{"onepass_relay":1}"#.utf8)
    /// `sizeof(sockaddr_un.sun_path)`, terminating NUL included.
    static let sunPathSize = 104

    /// `anchor apple generic`, the team's certificate and the exact
    /// identifier: what the listener must satisfy.
    public static func requirement(team: String, identifier: String = appIdentifier) -> String? {
        guard isTeamId(team) else { return nil }
        return #"anchor apple generic and certificate leaf[subject.OU] = "\#(team)" and identifier "\#(identifier)""#
    }

    static func isTeamId(_ s: String) -> Bool {
        s.utf8.count == 10 && s.utf8.allSatisfy { (0x30...0x39).contains($0) || (0x41...0x5A).contains($0) }
    }

    /// The team that signed this process, or nil (ad hoc: no production bridge).
    public static func ownTeam() -> String? {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
        var info: CFDictionary?
        guard
            SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info)
                == errSecSuccess,
            let dict = info as? [String: Any],
            let team = dict[kSecCodeInfoTeamIdentifier as String] as? String, isTeamId(team)
        else { return nil }
        return team
    }

    /// What the check of the listener found.
    public enum Listener: Equatable, Sendable {
        /// Identified, and it satisfies the requirement.
        case verified
        /// The App Sandbox refused the lookup (EPERM): nothing is known.
        case lookupDenied
        /// Identified as something else, or unreadable: refused.
        case refused
    }

    /// `kPOSIXErrorBase + EPERM`: what the guest lookup returns when the
    /// App Sandbox refuses it.
    static let lookupDeniedStatus: OSStatus = 100_000 + EPERM

    /// The verdict from the lookup status and, when it succeeded, the
    /// validity check's status.
    static func verdict(lookup: OSStatus, validity: OSStatus?) -> Listener {
        if lookup == lookupDeniedStatus { return .lookupDenied }
        guard lookup == errSecSuccess, let validity else { return .refused }
        return validity == errSecSuccess ? .verified : .refused
    }

    /// Checks the process at the other end of `fd` against `requirement`,
    /// identified by its audit token (never by pid, which can be reused).
    public static func checkPeer(fd: Int32, requirement text: String) -> Listener {
        var token = audit_token_t()
        var len = socklen_t(MemoryLayout<audit_token_t>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &len) == 0,
            Int(len) == MemoryLayout<audit_token_t>.size
        else { return .refused }
        let data = withUnsafeBytes(of: &token) { Data($0) }
        var code: SecCode?
        let attrs = [kSecGuestAttributeAudit: data] as CFDictionary
        let lookup = SecCodeCopyGuestWithAttributes(nil, attrs, [], &code)
        guard lookup == errSecSuccess, let code else { return verdict(lookup: lookup, validity: nil) }
        var req: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, [], &req) == errSecSuccess, let req else {
            return .refused
        }
        return verdict(lookup: lookup, validity: SecCodeCheckValidity(code, [], req))
    }

    /// Whether the extension may talk to this listener: verified, or the
    /// sandbox forbids the check (see the type's documentation).
    public static func acceptsListener(_ l: Listener) -> Bool {
        l != .refused
    }

    /// The launcher for the app's socket, or nil when this build is not
    /// signed by a team or has no App Group container.
    public static func launcher() -> AppSocketLauncher? {
        guard let team = ownTeam(), let requirement = requirement(team: team),
            let dir = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: "\(team).\(groupSuffix)")
        else { return nil }
        let path = dir.appendingPathComponent(socketName).path
        return AppSocketLauncher(path: path) { fd in acceptsListener(checkPeer(fd: fd, requirement: requirement)) }
    }
}

/// Connects to the app's socket, once per extension connection. Fails with
/// `.unavailable` when the app is not running (no socket, or nobody
/// listening) or when the listener is not the OnePass app of this team.
public struct AppSocketLauncher: HostLauncher {
    public let path: String
    public let verifyListener: @Sendable (Int32) -> Bool

    public init(path: String, verifyListener: @escaping @Sendable (Int32) -> Bool) {
        self.path = path
        self.verifyListener = verifyListener
    }

    public func launch() throws -> any HostProcess {
        let bytes = Array(path.utf8)
        guard bytes.count < AppSocket.sunPathSize else { throw RelayError.unavailable }
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw RelayError.unavailable }
        var on: Int32 = 1
        // A closed app must make our write fail with EPIPE, not kill the
        // extension process with SIGPIPE.
        _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            for (i, b) in bytes.enumerated() { raw[i] = b }
        }
        let connected = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connected == 0, verifyListener(fd) else {
            close(fd)
            throw RelayError.unavailable
        }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        do {
            try handle.write(contentsOf: Framing.encode(AppSocket.opening))
        } catch {
            throw RelayError.unavailable
        }
        return SocketHost(handle: handle)
    }
}

/// The app at the other end of a socket: one descriptor both ways.
final class SocketHost: HostProcess, @unchecked Sendable {
    private let handle: FileHandle
    private let lock = NSLock()
    private var done = false

    init(handle: FileHandle) {
        self.handle = handle
    }

    var input: FileHandle { handle }
    var output: FileHandle { handle }

    func terminate() {
        lock.lock()
        defer { lock.unlock() }
        guard !done else { return }
        done = true
        // Wakes the reader thread (end of stream) and tells the app the
        // connection is over; the descriptor closes with the handle.
        shutdown(handle.fileDescriptor, SHUT_RDWR)
    }
}
