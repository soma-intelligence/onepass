import Foundation
import Testing

@testable import VaultKit

#if canImport(CloudKit)
/// `apple/cloudkit/RemoteMessage.ckdb` is the CloudKit schema of the agent channel (agent-ready spec
/// 5.2, ruling 10). CloudKit refuses a query on a field that has no index, so the file must keep the
/// three indexes the channel's queries use: `to` (subscription and reads), `expires_at` (purge, `<`,
/// also sortable) and `recordName`.
@Suite("Remote channel CloudKit schema")
struct RemoteChannelSchemaTests {
    private static let schema: String = {
        let apple = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        return (try? String(contentsOf: apple.appendingPathComponent("cloudkit/RemoteMessage.ckdb"), encoding: .utf8)) ?? ""
    }()

    /// The line that declares `field`, without its trailing comma.
    private static func line(for field: String) -> String? {
        schema.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
            .first { $0.hasPrefix(field + " ") || $0.hasPrefix("\"" + field + "\" ") }
    }

    @Test func recordTypeIsTheChannelsOne() {
        #expect(Self.schema.contains("RECORD TYPE \(CloudKitRemoteChannel.recordType) ("))
    }

    @Test func recipientIsQueryable() throws {
        let line = try #require(Self.line(for: CloudKitRemoteChannel.Field.to))
        #expect(line.contains("STRING") && line.contains("QUERYABLE"))
    }

    @Test func expiryIsQueryableAndSortable() throws {
        let line = try #require(Self.line(for: CloudKitRemoteChannel.Field.expiresAt))
        #expect(line.contains("TIMESTAMP") && line.contains("QUERYABLE") && line.contains("SORTABLE"))
    }

    @Test func recordNameIsQueryable() throws {
        let line = try #require(Self.line(for: "___recordID"))
        #expect(line.contains("REFERENCE") && line.contains("QUERYABLE"))
    }

    @Test func blobIsPlainBytes() throws {
        let line = try #require(Self.line(for: CloudKitRemoteChannel.Field.blob))
        #expect(line.contains("BYTES") && !line.contains("QUERYABLE"))
    }
}
#endif
