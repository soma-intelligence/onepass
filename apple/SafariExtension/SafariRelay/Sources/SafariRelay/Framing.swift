import Foundation

/// Native messaging framing (milestone 4 spec, section 5): a 32-bit
/// little-endian length, then that many bytes of UTF-8 JSON. The same frames
/// the Chrome and Firefox native host reads on stdin and writes on stdout.
public enum Framing {
    /// OnePass cap, both directions (spec 5): 1 MiB.
    public static let maxFrame = 1 << 20

    /// The frame for `body`: length prefix, then the body.
    public static func encode(_ body: Data) throws(RelayError) -> Data {
        guard body.count <= maxFrame else { throw .tooLarge }
        var length = UInt32(body.count).littleEndian
        var out = Data(bytes: &length, count: 4)
        out.append(body)
        return out
    }

    /// The next frame of `source`. `nil` on a clean end of stream (between
    /// two frames); `.truncated` when the stream ends inside a frame;
    /// `.tooLarge` when the announced length exceeds the cap, without
    /// reading the body.
    public static func read(from source: some ByteSource) throws(RelayError) -> Data? {
        guard let header = try readExactly(4, from: source, allowEmpty: true) else { return nil }
        let length = header.withUnsafeBytes { raw in
            UInt32(littleEndian: raw.loadUnaligned(as: UInt32.self))
        }
        guard Int(length) <= maxFrame else { throw .tooLarge }
        guard length > 0 else { return Data() }
        guard let body = try readExactly(Int(length), from: source, allowEmpty: false) else {
            throw .truncated
        }
        return body
    }

    /// Exactly `count` bytes, or `nil` when the stream is already at its end
    /// and `allowEmpty` (a clean end of stream).
    private static func readExactly(
        _ count: Int, from source: some ByteSource, allowEmpty: Bool
    ) throws(RelayError) -> Data? {
        var out = Data()
        out.reserveCapacity(count)
        while out.count < count {
            let chunk: Data
            do {
                chunk = try source.read(upTo: count - out.count)
            } catch {
                throw .transport
            }
            if chunk.isEmpty {
                if out.isEmpty && allowEmpty { return nil }
                throw .truncated
            }
            out.append(chunk)
        }
        return out
    }
}

/// A blocking byte stream: an empty result is the end of the stream.
public protocol ByteSource {
    func read(upTo count: Int) throws -> Data
}

extension FileHandle: ByteSource {
    public func read(upTo count: Int) throws -> Data {
        try read(upToCount: count) ?? Data()
    }
}
