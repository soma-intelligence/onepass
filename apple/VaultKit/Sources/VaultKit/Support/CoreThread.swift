import Foundation

/// Runs a blocking Rust core call off the main thread, on a dedicated thread with a large stack.
///
/// Swift concurrency threads (and `Task.detached`) have 512 KiB stacks; SLH-DSA signature
/// verification in the core keeps big arrays on the stack (more so in debug builds) and
/// overflows them. One short-lived thread per heavy call (unlock, load, write) is cheap enough.
public enum CoreThread {
    public static let stackSize = 16 << 20

    public static func run<T: Sendable>(_ work: @escaping @Sendable () throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            let thread = Thread {
                continuation.resume(with: Result { try work() })
            }
            thread.stackSize = stackSize
            thread.qualityOfService = .userInitiated
            thread.name = "me.somalabs.onepass.core"
            thread.start()
        }
    }
}
