import Foundation
import Testing

@testable import VaultKit

#if canImport(CloudKit)
import CloudKit

/// `apple/cloudkit/RemoteMessage.ckdb` is the CloudKit schema of the container: the agent channel
/// (agent-ready spec 5.2, ruling 10), the vault sync type and the built-in `Users`. CloudKit refuses
/// a query on a field that has no index, so the file must keep the three indexes the channel's
/// queries use: `to` (subscription and reads), `expires_at` (purge, `<`, also sortable) and
/// `recordName`. The file is hand-written: the whole-file checks below stand in for
/// `cktool validate-schema`, which needs a management token.
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

    // MARK: - Whole-file check (no management token here: `cktool validate-schema` runs on the founder's Mac)

    /// One parsed `RECORD TYPE`: user fields (system `___` fields left out) to their type and indexes.
    struct RecordType {
        var fields: [String: (type: String, indexes: Set<String>)] = [:]
        var systemFields: Set<String> = []
        var grants: [String] = []
    }

    static let fieldTypes: Set<String> = [
        "ASSET", "BYTES", "DOUBLE", "INT64", "LOCATION", "REFERENCE", "STRING", "TIMESTAMP",
    ]
    static let indexKinds: Set<String> = ["QUERYABLE", "SORTABLE", "SEARCHABLE"]

    /// Parses the CloudKit schema language as `cktool export-schema` writes it, failing on anything
    /// else: `DEFINE SCHEMA`, then `RECORD TYPE <name> ( <field> <type> [indexes], ..., GRANT ... );`.
    static func parse(_ text: String) throws -> [String: RecordType] {
        struct SchemaError: Error, CustomStringConvertible { let description: String }
        var lines = text.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        guard lines.first == "DEFINE SCHEMA" else { throw SchemaError(description: "missing DEFINE SCHEMA") }
        lines.removeFirst()
        var types: [String: RecordType] = [:]
        var current: (name: String, type: RecordType)?
        for line in lines {
            if current == nil {
                let parts = line.split(separator: " ").map(String.init)
                guard parts.count == 4, parts[0] == "RECORD", parts[1] == "TYPE", parts[3] == "(" else {
                    throw SchemaError(description: "expected RECORD TYPE <name> (, found: \(line)")
                }
                guard types[parts[2]] == nil else { throw SchemaError(description: "\(parts[2]) declared twice") }
                current = (parts[2], RecordType())
                continue
            }
            if line == ");" {
                guard let done = current else { continue }
                guard !done.type.grants.isEmpty else { throw SchemaError(description: "\(done.name): no GRANT") }
                types[done.name] = done.type
                current = nil
                continue
            }
            let afterGrant = !current!.type.grants.isEmpty
            let isLastLine = !line.hasSuffix(",")
            let body = isLastLine ? line : String(line.dropLast())
            if body.hasPrefix("GRANT ") {
                let grant = body.split(separator: " ").map(String.init)
                guard grant.count == 4, ["READ", "WRITE", "CREATE"].contains(grant[1]), grant[2] == "TO",
                      grant[3].hasPrefix("\""), grant[3].hasSuffix("\"")
                else { throw SchemaError(description: "bad grant: \(line)") }
                current!.type.grants.append(body)
                continue
            }
            guard !afterGrant else { throw SchemaError(description: "field after a GRANT: \(line)") }
            guard !isLastLine else { throw SchemaError(description: "a field must be followed by a comma: \(line)") }
            var tokens = body.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            guard tokens.count >= 2 else { throw SchemaError(description: "bad field: \(line)") }
            var name = tokens.removeFirst()
            if name.hasPrefix("\"") {
                guard name.count > 2, name.hasSuffix("\"") else { throw SchemaError(description: "bad quoting: \(line)") }
                name = String(name.dropFirst().dropLast())
            } else if ["to", "type", "grant", "record", "list"].contains(name.lowercased()) {
                throw SchemaError(description: "keyword \(name) used as a field name must be quoted")
            }
            guard name.range(of: "^[A-Za-z_][A-Za-z0-9_]*$", options: .regularExpression) != nil else {
                throw SchemaError(description: "bad field name: \(name)")
            }
            var type = tokens.removeFirst()
            if type == "ENCRYPTED" {
                guard !tokens.isEmpty else { throw SchemaError(description: "ENCRYPTED without a type: \(line)") }
                type += " " + tokens.removeFirst()
            }
            let base = type.replacingOccurrences(of: "ENCRYPTED ", with: "")
            let inner = base.hasPrefix("LIST<") && base.hasSuffix(">") ? String(base.dropFirst(5).dropLast()) : base
            guard fieldTypes.contains(inner) else { throw SchemaError(description: "unknown type \(type): \(line)") }
            let indexes = Set(tokens)
            guard indexes.isSubset(of: indexKinds) else { throw SchemaError(description: "unknown index: \(line)") }
            guard !(type.hasPrefix("ENCRYPTED") && !indexes.isEmpty) else {
                throw SchemaError(description: "an encrypted field cannot be indexed: \(line)")
            }
            guard current!.type.fields[name] == nil, !current!.type.systemFields.contains(name) else {
                throw SchemaError(description: "\(name) declared twice")
            }
            if name.hasPrefix("___") {
                current!.type.systemFields.insert(name)
            } else {
                current!.type.fields[name] = (type, indexes)
            }
        }
        guard current == nil else { throw SchemaError(description: "unterminated RECORD TYPE \(current!.name)") }
        return types
    }

    @Test func fileParses() throws {
        let types = try Self.parse(Self.schema)
        #expect(!types.isEmpty)
    }

    /// The parser itself refuses what CloudKit refuses (so a pass above means something).
    @Test(arguments: [
        "RECORD TYPE A (\n x STRING,\n GRANT READ TO \"_world\"\n);",
        "DEFINE SCHEMA\nRECORD TYPE A (\n x TEXT,\n GRANT READ TO \"_world\"\n);",
        "DEFINE SCHEMA\nRECORD TYPE A (\n to STRING,\n GRANT READ TO \"_world\"\n);",
        "DEFINE SCHEMA\nRECORD TYPE A (\n x STRING\n GRANT READ TO \"_world\"\n);",
        "DEFINE SCHEMA\nRECORD TYPE A (\n x ENCRYPTED BYTES QUERYABLE,\n GRANT READ TO \"_world\"\n);",
        "DEFINE SCHEMA\nRECORD TYPE A (\n x STRING,\n GRANT READ TO \"_world\"\n",
    ])
    func parserRefusesBrokenSchemas(text: String) {
        #expect(throws: (any Error).self) { try Self.parse(text) }
    }

    /// Every system field an export carries, so an import never drops one.
    static let systemFields: Set<String> = [
        "___createTime", "___createdBy", "___etag", "___modTime", "___modifiedBy", "___recordID",
    ]

    /// `import-schema` replaces the development schema with the file: the file must describe the whole
    /// container (every record type the code writes, plus the built-in `Users`), or an import would
    /// drop the vault sync type `OPRecord`.
    @Test func fileDescribesTheWholeContainer() throws {
        let types = try Self.parse(Self.schema)
        #expect(Set(types.keys) == ["Users", CloudKitMapping.recordType, CloudKitRemoteChannel.recordType])
        for (name, type) in types {
            #expect(type.systemFields == Self.systemFields, "\(name) system fields")
        }
        #expect(types["Users"]?.fields["roles"]?.type == "LIST<INT64>")
    }

    /// `RemoteMessage`: exactly the fields `CloudKitRemoteChannel` writes and reads.
    @Test func remoteMessageMatchesTheChannel() throws {
        let type = try #require(try Self.parse(Self.schema)[CloudKitRemoteChannel.recordType])
        #expect(Set(type.fields.keys) == [
            CloudKitRemoteChannel.Field.to, CloudKitRemoteChannel.Field.blob, CloudKitRemoteChannel.Field.expiresAt,
        ])
        #expect(type.fields[CloudKitRemoteChannel.Field.to]?.type == "STRING")
        #expect(type.fields[CloudKitRemoteChannel.Field.blob]?.type == "BYTES")
        #expect(type.fields[CloudKitRemoteChannel.Field.expiresAt]?.type == "TIMESTAMP")
    }

    /// `OPRecord`: exactly the fields `CloudKitMapping.record(from:zoneID:)` sets, with the same
    /// types, and `data` encrypted (it goes in `encryptedValues`).
    @Test func opRecordMatchesTheMapping() throws {
        let type = try #require(try Self.parse(Self.schema)[CloudKitMapping.recordType])
        let zone = CKRecordZone.ID(zoneName: CloudKitMapping.zoneName, ownerName: CKCurrentUserDefaultName)
        let remote = RemoteRecord(
            name: RecordName(kind: 5, id: "00112233445566778899aabbccddeeff"), version: 1, data: Data([1]),
            serverMeta: nil)
        let record = try CloudKitMapping.record(from: remote, zoneID: zone)
        let encrypted = Set(record.encryptedValues.allKeys())
        let plain = Set(record.allKeys()).subtracting(encrypted)
        #expect(Set(type.fields.keys) == plain.union(encrypted))
        for key in plain {
            #expect(type.fields[key]?.type == "INT64", "\(key)")
            #expect(record[key] is Int64, "\(key)")
        }
        for key in encrypted {
            #expect(type.fields[key]?.type == "ENCRYPTED BYTES", "\(key)")
        }
    }
}
#endif
