import Foundation

/// What the iPhone and the watch say to each other. Travels as a property-list dictionary
/// (`updateApplicationContext` or `transferUserInfo`): `"kind"` names the case, `"data"` carries
/// the bytes of `watchKey` and `payload`.
public enum CompanionMessage: Hashable, Sendable {
    /// Watch to iPhone: the watch public key (ML-KEM-1024 + X25519, 1600 bytes). Sent on every watch start.
    case watchKey(Data)
    /// iPhone to watch: the sealed payload (`Session.companionPayload`).
    case payload(Data)
    /// iPhone to watch: forget the payload, the key and the generation, then rekey.
    case wipe
    /// Watch to iPhone: the last payload was refused, send a fresh one.
    case refreshRequest

    private enum Kind: String {
        case watchKey, payload, wipe, refresh
    }

    public init?(dictionary: [String: Any]) {
        guard let raw = dictionary["kind"] as? String, let kind = Kind(rawValue: raw) else { return nil }
        switch kind {
        case .watchKey, .payload:
            guard let data = dictionary["data"] as? Data else { return nil }
            self = kind == .watchKey ? .watchKey(data) : .payload(data)
        case .wipe:
            self = .wipe
        case .refresh:
            self = .refreshRequest
        }
    }

    public var dictionary: [String: Any] {
        switch self {
        case .watchKey(let data): ["kind": Kind.watchKey.rawValue, "data": data]
        case .payload(let data): ["kind": Kind.payload.rawValue, "data": data]
        // The nonce keeps two wipes distinct: WatchConnectivity drops an application context
        // equal to the previous one.
        case .wipe: ["kind": Kind.wipe.rawValue, "nonce": UUID().uuidString]
        case .refreshRequest: ["kind": Kind.refresh.rawValue]
        }
    }
}
