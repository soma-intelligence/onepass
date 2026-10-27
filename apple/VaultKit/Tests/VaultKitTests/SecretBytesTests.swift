import Foundation
import Synchronization
import Testing

@testable import VaultKit

@Suite("SecretBytes")
struct SecretBytesTests {
    static let sample = "motdepasse-fictif-0123456789"

    @Test func holdsACopyOfTheBytes() {
        var source = Data(Self.sample.utf8)
        let secret = SecretBytes(copying: source)
        #expect(secret.count == source.count)
        #expect(secret.string() == Self.sample)
        #expect(secret.withData { $0 } == source)
        // Independent buffer: changing the source leaves the secret intact.
        source.resetBytes(in: 0..<source.count)
        #expect(secret.string() == Self.sample)
    }

    @Test func takingWipesAndEmptiesTheSource() {
        var source = Data(Self.sample.utf8)
        let secret = SecretBytes(taking: &source)
        #expect(source.isEmpty)
        #expect(secret.string() == Self.sample)
    }

    /// The buffer stays allocated until `deinit`: reading it after `wipe()` is safe.
    @Test func wipeOverwritesTheBuffer() {
        let secret = SecretBytes(utf8: Self.sample)
        let count = secret.count
        let address = secret.testBaseAddress
        #expect(UnsafeRawBufferPointer(start: address, count: count).contains { $0 != 0 })

        secret.wipe()
        let after = Array(UnsafeRawBufferPointer(start: address, count: count))
        #expect(after == [UInt8](repeating: 0, count: count))
        #expect(secret.isEmpty)
        #expect(secret.string() == "")
        withExtendedLifetime(secret) {}
    }

    /// `deinit` wipes before it frees: the hook sees the still allocated buffer, never freed memory.
    @Test func deinitWipesBeforeFreeing() {
        let seen = Mutex<[UInt8]?>(nil)
        do {
            let secret = SecretBytes(utf8: Self.sample)
            secret.onDeinit = { buffer in seen.withLock { $0 = Array(buffer) } }
            #expect(secret.count == Self.sample.utf8.count)
        }
        let bytes = seen.withLock { $0 }
        #expect(bytes != nil)
        #expect(bytes?.allSatisfy { $0 == 0 } == true)
        #expect((bytes?.count ?? 0) >= Self.sample.utf8.count)
    }

    @Test func withDataHandsACopy() {
        let secret = SecretBytes(utf8: Self.sample)
        let length = secret.withData { $0.count }
        #expect(length == Self.sample.utf8.count)
        // The secret keeps its bytes after the temporary copy was wiped.
        #expect(secret.string() == Self.sample)
    }

    @Test func descriptionsNeverShowTheBytes() {
        let secret = SecretBytes(utf8: Self.sample)
        #expect(secret.description == "SecretBytes(**)")
        #expect(secret.debugDescription == "SecretBytes(**)")
        #expect("\(secret)" == "SecretBytes(**)")
        #expect(String(reflecting: secret) == "SecretBytes(**)")
        var dumped = ""
        dump(secret, to: &dumped)
        #expect(!dumped.contains(Self.sample))
        #expect(Mirror(reflecting: secret).children.isEmpty)
    }

    @Test func utf8CheckDoesNotNeedAString() {
        #expect(SecretBytes(utf8: "clé-éèà").isValidUTF8)
        #expect(SecretBytes(copying: Data()).isValidUTF8)
        #expect(!SecretBytes(copying: Data([0x41, 0xC3])).isValidUTF8)
        #expect(!SecretBytes(copying: Data([0xFF, 0xFE])).isValidUTF8)
    }

    @Test func emptyInputIsFine() {
        let secret = SecretBytes(copying: Data())
        #expect(secret.isEmpty)
        #expect(secret.string() == "")
        secret.wipe()
        #expect(secret.isEmpty)
    }
}
