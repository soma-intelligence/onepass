import XCTest
@testable import VaultKit

final class IconHashTests: XCTestCase {
    private struct Vector: Decodable { let name: String; let png: String; let hash: String }

    private func vectors() throws -> [Vector] {
        // apple/VaultKit/Tests/VaultKitTests/IconHashTests.swift -> repository root
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { url.deleteLastPathComponent() }
        url.appendPathComponent("scripts/testdata/dhash-vectors.json")
        return try JSONDecoder().decode([Vector].self, from: Data(contentsOf: url))
    }

    func testSharedVectorsMatchPython() throws {
        let all = try vectors()
        XCTAssertEqual(all.count, 11)
        for v in all {
            let data = try XCTUnwrap(Data(base64Encoded: v.png), v.name)
            let hash = try XCTUnwrap(IconHash.dHash(data), v.name)
            if v.name == "low-alpha-mark" {
                // At alpha 1 to 20 CoreGraphics keeps premultiplied 8-bit channels (0 to 20 levels),
                // so un-premultiplying cannot give back the straight colour Python hashes. Exact
                // equality is impossible there; one bit of drift is observed, allow at most 2.
                let expected = try XCTUnwrap(UInt64(v.hash, radix: 16))
                XCTAssertLessThanOrEqual(IconHash.distance(hash, expected), 2, v.name)
            } else {
                XCTAssertEqual(String(format: "%016llx", hash), v.hash, v.name)
            }
        }
    }

    func testHugeDeclaredSizeIsRefused() {
        // A valid PNG signature and IHDR claiming 100000 x 100000, no pixel data at all.
        func chunk(_ kind: String, _ body: [UInt8]) -> [UInt8] {
            var out = withUnsafeBytes(of: UInt32(body.count).bigEndian) { Array($0) }
            out += Array(kind.utf8) + body
            let crc = (Array(kind.utf8) + body).reduce(UInt32.max) { crc, byte in
                (0..<8).reduce(crc ^ UInt32(byte)) { c, _ in c & 1 == 1 ? 0xEDB88320 ^ (c >> 1) : c >> 1 }
            } ^ UInt32.max
            return out + withUnsafeBytes(of: crc.bigEndian) { Array($0) }
        }
        let side = withUnsafeBytes(of: UInt32(100_000).bigEndian) { Array($0) }
        let png = [UInt8]([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
            + chunk("IHDR", side + side + [8, 6, 0, 0, 0]) + chunk("IEND", [])
        XCTAssertNil(IconHash.dHash(Data(png)))
    }

    func testDistanceAndGarbage() {
        XCTAssertEqual(IconHash.distance(0, 0), 0)
        XCTAssertEqual(IconHash.distance(0, UInt64.max), 64)
        XCTAssertEqual(IconHash.distance(0b1011, 0b0001), 2)
        XCTAssertNil(IconHash.dHash(Data("not an image".utf8)))
    }
}
