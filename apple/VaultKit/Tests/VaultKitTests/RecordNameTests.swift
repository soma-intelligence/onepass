import Foundation
import Testing

@testable import VaultKit

@Suite("Record name")
struct RecordNameTests {
    static let hex = "00112233445566778899aabbccddeeff"

    @Test func recordNameRoundtrips() throws {
        let name = RecordName(kind: 5, id: Self.hex)
        #expect(name.string == "5.\(Self.hex)")
        let parsed = try #require(RecordName(string: name.string))
        #expect(parsed == name)
        #expect(parsed.kind == 5 && parsed.id == Self.hex)

        for kind: UInt8 in [1, 6] {
            let other = RecordName(kind: kind, id: Self.hex)
            #expect(RecordName(string: other.string) == other)
        }
    }

    @Test func malformedNamesAreRejected() {
        let rejected = [
            "", "5", "5.", ".\(Self.hex)", "x.\(Self.hex)", "256.\(Self.hex)", "-1.\(Self.hex)",
            "5.\(Self.hex.uppercased())", "5.\(Self.hex)0", "5.\(Self.hex.dropLast())", "5.\(Self.hex).1",
            "5.0011223344556677889zaabbccddeeff", " 5.\(Self.hex)", "05.\(Self.hex)",
        ]
        for string in rejected {
            #expect(RecordName(string: string) == nil, "\(string)")
        }
    }
}
