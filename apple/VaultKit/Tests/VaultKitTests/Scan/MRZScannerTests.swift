import Foundation
import Testing

@testable import VaultKit

@Suite struct MRZScannerTests {
    static let l1 = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<"
    static let l2 = "L898902C36UTO7408122F1204159ZE184226B<<<<<10"
    /// What a text recognizer hands over: the page around the MRZ, spaces in the lines.
    static let page = "PASSPORT\nUtopia\n\(l1)\n\(l2.prefix(20)) \(l2.dropFirst(20))\n"

    @Test func needsThreeIdenticalReads() {
        var acc = MRZAccumulator()
        #expect(acc.add(Self.page) == nil)
        #expect(acc.add(Self.page) == nil)
        #expect(acc.add(Self.page) == [Self.l1, Self.l2])
    }

    @Test func ignoresInvalidLines() {
        var acc = MRZAccumulator()
        let badDigit = "\(Self.l1)\n\(Self.l2.replacingOccurrences(of: "C36", with: "C35"))"
        #expect(acc.add(Self.page) == nil)
        #expect(acc.add(badDigit) == nil)
        #expect(acc.add("no MRZ here") == nil)
        #expect(acc.add(Self.page) == nil)
        #expect(acc.add(Self.page) == [Self.l1, Self.l2])
    }

    @Test func aDifferentValidReadStartsOver() {
        var acc = MRZAccumulator()
        let other = "P<UTOERIKSSON<<ANNA<<<<<<<<<<<<<<<<<<<<<<<<<\n\(Self.l2)"
        #expect(acc.add(Self.page) == nil)
        #expect(acc.add(Self.page) == nil)
        #expect(acc.add(other) == nil)
        #expect(acc.add(Self.page) == nil)
        #expect(acc.add(Self.page) == nil)
        #expect(acc.add(Self.page) == [Self.l1, Self.l2])
    }
}
