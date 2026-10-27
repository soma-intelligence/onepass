import Foundation

/// Name of a record on the server: `"<kind code>.<id hex>"`, for example `"5.00112233445566778899aabbccddeeff"`.
/// The kind is the core record kind code (1 to 9), the id its 32 lowercase hex characters.
public struct RecordName: Hashable, Sendable, CustomStringConvertible {
    public var kind: UInt8
    public var id: String

    public init(kind: UInt8, id: String) {
        self.kind = kind
        self.id = id
    }

    /// Canonical form only: decimal kind without leading zero, a dot, 32 lowercase hex characters.
    public init?(string: String) {
        let parts = string.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 2 else { return nil }
        let kindText = parts[0]
        let idText = parts[1]
        guard !kindText.isEmpty, kindText.allSatisfy({ $0.isASCII && $0.isNumber }),
            kindText == "0" || !kindText.hasPrefix("0"),
            let kind = UInt8(kindText)
        else { return nil }
        guard idText.utf8.count == 32,
            idText.utf8.allSatisfy({ (0x30...0x39).contains($0) || (0x61...0x66).contains($0) })
        else { return nil }
        self.kind = kind
        self.id = String(idText)
    }

    public var string: String { "\(kind).\(id)" }
    public var description: String { string }
}
