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
/// "frame": <JSON text of one bridge envelope, send only>}`.
///
/// The envelope travels as text and is relayed byte for byte: the relay never
/// parses or re-serializes protocol JSON (spec R-03, one protocol to audit).
public struct RelayRequest: Equatable, Sendable {
    public enum Op: Equatable, Sendable {
        case open
        case send(frame: Data)
        case poll
        case close
    }

    public static let version = 1

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
        let allowed: Set<String> = ["onepass", "op", "conn", "frame"]
        guard Set(dict.keys).isSubset(of: allowed) else { throw .badRequest }
        guard let v = dict["onepass"] as? NSNumber, !isBool(v), v.intValue == version,
            v.doubleValue == Double(version)
        else { throw .badRequest }
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

/// The relay's answer: `{"ok": true, "frames": [<JSON text>], "closed": Bool}`
/// or `{"ok": false, "error": <code>}`.
public enum RelayResponse: Equatable, Sendable {
    case ok(frames: [String], closed: Bool)
    case failure(RelayError)

    public var dictionary: [String: Any] {
        switch self {
        case .ok(let frames, let closed):
            return ["ok": true, "frames": frames, "closed": closed]
        case .failure(let e):
            return ["ok": false, "error": e.rawValue]
        }
    }
}
