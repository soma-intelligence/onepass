import Foundation
import Testing

@testable import VaultKit

#if DEBUG
/// The AutoFill extension follows an isolated launch of the app (UI tests) through a marker in the
/// App Group container, and never opens the user's store meanwhile.
@Suite("UI test isolation")
struct UITestIsolationTests {
    private func container(shared: Bool) throws -> (SharedContainer, URL) {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("UITestIsolationTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return (SharedContainer(root: root, isShared: shared, defaultsSuite: nil), root)
    }

    @Test func markerSwitchesTheExtensionToTheIsolatedStore() throws {
        let (container, root) = try container(shared: true)
        defer { try? FileManager.default.removeItem(at: root) }
        #expect(UITestIsolation.extensionEnvironment(container: container) == nil)

        UITestIsolation.markActive(container: container)
        let environment = try #require(UITestIsolation.extensionEnvironment(container: container))
        let folder = root.appendingPathComponent("OnePassUITest", isDirectory: true)
        #expect(environment.databaseURL == folder.appendingPathComponent("vault.sqlite"))
        #expect(environment.databaseURL != container.databaseURL)
        #expect((environment.keychain as? SystemKeychain)?.service == UITestIsolation.keychainService)
        #expect(environment.identityStore is NoIdentityStore)
        #expect(environment.settings.accountID == nil)
        // The extension never creates the isolated store either.
        #expect(!FileManager.default.fileExists(atPath: environment.databaseURL.path))

        UITestIsolation.clearMarker(container: container)
        #expect(UITestIsolation.extensionEnvironment(container: container) == nil)
    }

    @Test func noAppGroupMeansNoMarkerAndATemporaryStore() throws {
        let (container, root) = try container(shared: false)
        defer { try? FileManager.default.removeItem(at: root) }
        UITestIsolation.markActive(container: container)
        #expect(!UITestIsolation.isMarked(container: container))
        #expect(UITestIsolation.extensionEnvironment(container: container) == nil)
        #expect(UITestIsolation.folder(container: container).path.hasPrefix(FileManager.default.temporaryDirectory.path))
    }
}
#endif
