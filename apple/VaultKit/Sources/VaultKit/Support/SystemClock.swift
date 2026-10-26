import Foundation

public protocol BootClock: Sendable {
    /// Date the system booted (`kern.boottime`).
    var bootTime: Date { get }
    var now: Date { get }
}

public struct SystemClock: BootClock {
    public init() {}

    public var now: Date { Date() }

    public var bootTime: Date {
        var mib: [Int32] = [CTL_KERN, KERN_BOOTTIME]
        var value = timeval()
        var size = MemoryLayout<timeval>.stride
        guard sysctl(&mib, UInt32(mib.count), &value, &size, nil, 0) == 0 else {
            return Date.distantPast
        }
        return Date(timeIntervalSince1970: TimeInterval(value.tv_sec) + TimeInterval(value.tv_usec) / 1_000_000)
    }
}
