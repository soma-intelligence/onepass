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
        XCTAssertEqual(all.count, 10)
        for v in all {
            let data = try XCTUnwrap(Data(base64Encoded: v.png), v.name)
            let hash = try XCTUnwrap(IconHash.dHash(data), v.name)
            XCTAssertEqual(String(format: "%016llx", hash), v.hash, v.name)
        }
    }

    func testDistanceAndGarbage() {
        XCTAssertEqual(IconHash.distance(0, 0), 0)
        XCTAssertEqual(IconHash.distance(0, UInt64.max), 64)
        XCTAssertEqual(IconHash.distance(0b1011, 0b0001), 2)
        XCTAssertNil(IconHash.dHash(Data("not an image".utf8)))
    }
}
