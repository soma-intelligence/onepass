import Foundation

public protocol BootClock: Sendable {
    /// Identifier of the current boot (`kern.bootsessionuuid`); empty when unknown.
    var bootSessionID: String { get }
    var now: Date { get }
}

public struct SystemClock: BootClock {
    public init() {}

    public var now: Date { Date() }

    public var bootSessionID: String {
        var size = 0
        guard sysctlbyname("kern.bootsessionuuid", nil, &size, nil, 0) == 0, size > 1 else { return "" }
        var buffer = [CChar](repeating: 0, count: size)
        guard sysctlbyname("kern.bootsessionuuid", &buffer, &size, nil, 0) == 0 else { return "" }
        return String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
}
