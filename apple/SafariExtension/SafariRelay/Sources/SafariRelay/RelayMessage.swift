import Foundation

/// Stable error codes of the relay, sent to the extension (never a raw
/// system message, never a frame's content).
public enum RelayError: String, Error, Sendable, Equatable {
    /// The request is not a well-formed relay request.
    case badRequest = "bad_request"
    /// A frame is over the 1 MiB cap.
    case tooLarge = "too_large"
    /// A frame from the host ended early.
    case truncated
    /// A read or write on the host's pipes failed.
    case transport
    /// No connection with this id (closed, evicted, or never opened).
    case unknownConn = "unknown_conn"
    /// A connection with this id is already open.
    case exists
    /// A poll is already waiting on this connection.
    case busy
    /// No bridge host in this build, or it could not be started.
    case unavailable
}

/// One request of the extension, the dictionary given to
/// `browser.runtime.sendNativeMessage` (`extension/src/background/safari.ts`).
///
/// `{"onepass": 1, "op": "open" | "send" | "poll" | "close", "conn": <32 hex>,
/// "frame": <JSON text of one bridge envelope, send only>}`, or
/// `{"onepass": 1, "op": "open_app"}` (no connection: bring the app forward), or on iOS
/// `{"onepass": 1, "op": "vault_state" | "unlock_biometric"}` and
/// `{"onepass": 1, "op": "unlock_password", "password": <text>}` (the vault of the handler's own
/// process, `VaultGate`).
///
/// The envelope travels as text and is relayed byte for byte: the relay never
/// parses or re-serializes protocol JSON (spec R-03, one protocol to audit).
public struct RelayRequest: Equatable, Sendable {
    public enum Op: Equatable, Sendable {
        case open
        case send(frame: Data)
        case poll
        case close
        /// "Déverrouiller dans OnePass": bring the app forward, outside any bridge connection.
        case openApp
        /// iOS (spec 2026-11-03-ios-safari-autofill 4): the vault of this extension's own process.
        case vaultState
        /// Face ID or Touch ID, under the app's biometric policy.
        case unlockBiometric
        /// The master password typed in the unlock sheet, as UTF-8. The handler wipes its copy.
        case unlockPassword(Data)
    }

    public static let version = 1
    /// Longest master password accepted from the unlock sheet, in UTF-8 bytes.
    public static let maxPassword = 1024

    public let conn: String
    public let op: Op

    public init(conn: String, op: Op) {
        self.conn = conn
        self.op = op
    }

    /// Strict parse: unknown keys, a wrong version, a malformed id or a
    /// frame on anything but `send` are refused.
    public static func parse(_ message: Any?) throws(RelayError) -> RelayRequest {
        guard let dict = message as? [String: Any] else { throw .badRequest }
        let allowed: Set<String> = ["onepass", "op", "conn", "frame", "password"]
        guard Set(dict.keys).isSubset(of: allowed) else { throw .badRequest }
        guard let v = dict["onepass"] as? NSNumber, !isBool(v), v.intValue == version,
            v.doubleValue == Double(version)
        else { throw .badRequest }
        switch dict["op"] as? String {
        case "open_app", "vault_state", "unlock_biometric":
            guard dict.count == 2 else { throw .badRequest }
            let op: Op =
                switch dict["op"] as? String {
                case "open_app": .openApp
                case "vault_state": .vaultState
                default: .unlockBiometric
                }
            return RelayRequest(conn: "", op: op)
        case "unlock_password":
            guard dict.count == 3, let text = dict["password"] as? String, !text.isEmpty,
                text.utf8.count <= maxPassword
            else { throw .badRequest }
            return RelayRequest(conn: "", op: .unlockPassword(Data(text.utf8)))
        default:
            break
        }
        guard dict["password"] == nil else { throw .badRequest }
        guard let conn = dict["conn"] as? String, isConnId(conn) else { throw .badRequest }
        guard let opName = dict["op"] as? String else { throw .badRequest }
        let frame = dict["frame"]
        switch opName {
        case "send":
            guard let text = frame as? String else { throw .badRequest }
            let bytes = Data(text.utf8)
            guard bytes.count <= Framing.maxFrame else { throw .tooLarge }
            return RelayRequest(conn: conn, op: .send(frame: bytes))
        case "open", "poll", "close":
            guard frame == nil else { throw .badRequest }
            let op: Op = opName == "open" ? .open : opName == "poll" ? .poll : .close
            return RelayRequest(conn: conn, op: op)
        default:
            throw .badRequest
        }
    }

    /// 32 lowercase hexadecimal characters (16 random bytes).
    static func isConnId(_ s: String) -> Bool {
        s.utf8.count == 32 && s.utf8.allSatisfy { (0x30...0x39).contains($0) || (0x61...0x66).contains($0) }
    }

    private static func isBool(_ n: NSNumber) -> Bool {
        CFGetTypeID(n) == CFBooleanGetTypeID()
    }
}

/// The relay's answer: `{"ok": true, "frames": [<JSON text>], "closed": Bool}`,
/// `{"ok": true, "vault": {...}}` (`VaultReply`) or `{"ok": false, "error": <code>}`.
public enum RelayResponse: Equatable, Sendable {
    case ok(frames: [String], closed: Bool)
    case vault(VaultReply)
    case failure(RelayError)

    public var dictionary: [String: Any] {
        switch self {
        case .ok(let frames, let closed):
            return ["ok": true, "frames": frames, "closed": closed]
        case .vault(let reply):
            return ["ok": true, "vault": reply.dictionary]
        case .failure(let e):
            return ["ok": false, "error": e.rawValue]
        }
    }
}

/// The vault of the handler's own process, as the unlock sheet sees it. No secret, no item data.
public struct VaultReply: Equatable, Sendable {
    /// Why an unlock did not open the vault. Stable codes, shown by the sheet in its own words.
    public enum Failure: String, Sendable {
        /// The biometric policy asks for the master password (reboot, 14 days, biometry changed,
        /// not enrolled, or the user chose the password).
        case passwordRequired = "password_required"
        case wrongPassword = "wrong_password"
        case cancelled
        /// Too many wrong passwords: the app's lockout holds.
        case lockedOut = "locked_out"
        case noAccount = "no_account"
        case failed
    }

    public var locked: Bool
    /// The account's display name (or empty).
    public var account: String
    /// `faceID`, `touchID`, `opticID`, or `none` when biometric unlock cannot be used now.
    public var biometry: String
    /// Set after a refused unlock.
    public var failure: Failure?
    /// The localized reason the password is required, when the policy says so.
    public var message: String?

    public init(
        locked: Bool, account: String = "", biometry: String = "none", failure: Failure? = nil,
        message: String? = nil
    ) {
        self.locked = locked
        self.account = account
        self.biometry = biometry
        self.failure = failure
        self.message = message
    }

    public var dictionary: [String: Any] {
        var d: [String: Any] = ["locked": locked, "account": account, "biometry": biometry]
        if let failure { d["error"] = failure.rawValue }
        if let message { d["message"] = message }
        return d
    }
}

/// What the iOS handler does for the unlock sheet (spec 2026-11-03-ios-safari-autofill 4).
/// Called off the main thread; each call blocks until the answer is known.
public protocol VaultGate: Sendable {
    func state() -> VaultReply
    func unlockBiometric() -> VaultReply
    /// The caller passes the only copy it keeps; the gate wipes what it derives from it.
    func unlockPassword(_ password: Data) -> VaultReply
}
