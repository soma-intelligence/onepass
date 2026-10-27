import Foundation

/// Secret bytes (AUK, Secret Key, master password) in one heap buffer that this object alone owns.
/// `wipe()` overwrites it with `memset_s` (never optimized away), and `deinit` wipes it again before
/// freeing it. The buffer is allocated directly, never through `Data` or `Array`, so no copy-on-write
/// copy can escape the wipe.
///
/// Not `Equatable`, not `Hashable`, and `description`, `debugDescription` and the mirror are masked:
/// interpolating it in a log or a test failure shows `SecretBytes(**)`.
///
/// Limits (R5): bytes handed out through `withUnsafeBytes`, `withData` or `string()` are copies the
/// caller owns (`withData` wipes its own temporary `Data` afterwards); `String` copies cannot be wiped,
/// nor copies made by the bindings or the core.
///
/// `Sendable` because the unlock paths hand it from the core thread to the main actor: every access
/// to the buffer goes through a lock, so a `wipe()` from one thread never races a read on another.
public final class SecretBytes: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    /// Never resized; deallocated in `deinit` only.
    private let storage: UnsafeMutableRawBufferPointer
    /// Bytes in use (0 once wiped).
    private var length: Int

    #if DEBUG
    /// Tests: runs in `deinit` after the wipe and before the buffer is freed, with the (still
    /// allocated) buffer, so a test can check that the bytes were overwritten without reading
    /// freed memory.
    var onDeinit: (@Sendable (UnsafeRawBufferPointer) -> Void)?
    #endif

    /// Copies `bytes` into a fresh buffer (the caller wipes its own copy).
    public init(copying bytes: some ContiguousBytes) {
        let (storage, length) = bytes.withUnsafeBytes { source -> (UnsafeMutableRawBufferPointer, Int) in
            let storage = UnsafeMutableRawBufferPointer.allocate(byteCount: max(source.count, 1), alignment: 1)
            if let base = source.baseAddress, source.count > 0 {
                storage.baseAddress!.copyMemory(from: base, byteCount: source.count)
            }
            return (storage, source.count)
        }
        self.storage = storage
        self.length = length
    }

    /// The UTF-8 bytes of `string`. The `String` itself cannot be wiped: drop it right after (R5).
    public convenience init(utf8 string: String) {
        var bytes = Array(string.utf8)
        self.init(copying: bytes)
        bytes.withUnsafeMutableBytes { Self.zero($0) }
    }

    /// Copies `source`, then overwrites it and leaves it empty. The overwrite reaches the original bytes
    /// only when `source` is their sole owner: if another `Data` shares the buffer (then
    /// `withUnsafeMutableBytes` copies before writing) or a `CFData`/`NSData` held elsewhere backs it
    /// (bindings, Security framework), only that fresh copy is wiped and the original may survive (R5).
    public convenience init(taking source: inout Data) {
        self.init(copying: source)
        source.withUnsafeMutableBytes { Self.zero($0) }
        source = Data()
    }

    deinit {
        Self.zero(storage)
        #if DEBUG
        onDeinit?(UnsafeRawBufferPointer(storage))
        #endif
        storage.deallocate()
    }

    /// Number of bytes held (0 once wiped).
    public var count: Int { lock.withLock { length } }

    public var isEmpty: Bool { count == 0 }

    /// Read access to the bytes. The pointer must not escape `body`.
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try lock.withLock {
            try body(UnsafeRawBufferPointer(rebasing: storage[0..<length]))
        }
    }

    /// A temporary `Data` copy for an API that takes `Data` (FFI, Secure Enclave), overwritten when
    /// `body` returns. Copies `body` keeps (or the callee makes) are out of reach.
    public func withData<R>(_ body: (Data) throws -> R) rethrows -> R {
        var data = withUnsafeBytes { Data($0) }
        defer { data.withUnsafeMutableBytes { Self.zero($0) } }
        return try body(data)
    }

    /// The bytes as UTF-8 text, for an API that only takes `String` (nil if not UTF-8). The result is a
    /// copy that cannot be wiped: keep it in a local, never in a property (R5).
    public func string() -> String? {
        withUnsafeBytes { String(bytes: $0, encoding: .utf8) }
    }

    /// Whether the bytes are valid UTF-8, checked in place (no `String` is built).
    public var isValidUTF8: Bool {
        withUnsafeBytes { buffer in
            var iterator = buffer.makeIterator()
            var decoder = Unicode.UTF8()
            while true {
                switch decoder.decode(&iterator) {
                case .scalarValue: continue
                case .emptyInput: return true
                case .error: return false
                }
            }
        }
    }

    /// Overwrites the bytes now; the object then holds nothing (`count` 0). Idempotent.
    public func wipe() {
        lock.withLock {
            Self.zero(storage)
            length = 0
        }
    }

    #if DEBUG
    /// Tests: the buffer's address, to read it after `wipe()` (it stays allocated until `deinit`).
    var testBaseAddress: UnsafeRawPointer { UnsafeRawPointer(storage.baseAddress!) }
    #endif

    /// `memset_s`: unlike `memset`, the compiler may not drop it as a dead store.
    static func zero(_ buffer: UnsafeMutableRawBufferPointer) {
        guard let base = buffer.baseAddress, buffer.count > 0 else { return }
        _ = memset_s(base, buffer.count, 0, buffer.count)
    }
}

extension SecretBytes: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "SecretBytes(**)" }
    public var debugDescription: String { "SecretBytes(**)" }
    public var customMirror: Mirror { Mirror(self, children: [], displayStyle: .class) }
}
