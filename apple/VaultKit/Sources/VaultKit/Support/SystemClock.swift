import Foundation

public protocol BootClock: Sendable {
    /// Identifier of the current boot (`kern.bootsessionuuid`); empty when unknown.
    var bootSessionID: String { get }
    /// Wall clock time of the current boot (`kern.boottime`); nil when unknown. Read where the boot
    /// session id is not (an extension's sandbox may refuse that sysctl).
    var bootTime: Date? { get }
    var now: Date { get }
}

extension BootClock {
    public var bootTime: Date? { nil }
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

    public var bootTime: Date? {
        var value = timeval()
        var size = MemoryLayout<timeval>.size
        guard sysctlbyname("kern.boottime", &value, &size, nil, 0) == 0, value.tv_sec > 0 else { return nil }
        return Date(timeIntervalSince1970: TimeInterval(value.tv_sec) + TimeInterval(value.tv_usec) / 1_000_000)
    }
}
