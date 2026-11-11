import Foundation
import Synchronization
import notify
#if os(macOS)
import AppKit
#endif

/// Tells whether the device was locked since a given moment, for the AutoFill unlock window.
public protocol DeviceLockSignal: Sendable {
    /// Starts watching. Nil when the system refuses: the caller then keeps no unlock (fail closed).
    func watch() -> (any DeviceLockWatch)?
}

public protocol DeviceLockWatch: AnyObject, Sendable {
    /// The lock state of the device changed since `watch()` (locked, or unlocked again), or the
    /// system can no longer tell. Once true, stays true.
    func changed() -> Bool
}

/// The system's lock signal. The only place that names it: swap `lockStateName` (or this type) if
/// the system stops posting it.
///
/// iOS and visionOS: a Darwin notification read as a counter (`notify_register_check`, then
/// `notify_check` at each use). A counter, not a callback, because the provider's process is
/// suspended between two requests: a post made meanwhile is still seen at the next use.
/// `lockStateName` is an UNDOCUMENTED system name (SpringBoard posts it when the device locks and
/// when it unlocks); `notify.h` itself is public API, usable from an app extension.
///
/// macOS: no Darwin name is known for the screen lock. The process is not suspended there, so the
/// distributed "screen is locked" notification (the one the app already locks on, undocumented
/// too), the system going to sleep and the user session resigning are latched as they arrive.
public struct SystemDeviceLockSignal: DeviceLockSignal {
    #if os(macOS)
    static let lockStateName = "com.apple.screenIsLocked"
    #else
    static let lockStateName = "com.apple.springboard.lockstate"
    #endif

    public init() {}

    public func watch() -> (any DeviceLockWatch)? {
        #if os(macOS)
        Watch()
        #else
        DarwinNotifyWatch(name: Self.lockStateName)
        #endif
    }

    #if os(macOS)
    private final class Watch: DeviceLockWatch {
        private let latched = Mutex(false)
        /// Written in `init`, read in `deinit` only.
        nonisolated(unsafe) private var observers: [(NotificationCenter, any NSObjectProtocol)] = []

        init() {
            let latch: @Sendable (Notification) -> Void = { [weak self] _ in self?.latched.withLock { $0 = true } }
            let distributed = DistributedNotificationCenter.default()
            let workspace = NSWorkspace.shared.notificationCenter
            observers = [
                (distributed, distributed.addObserver(
                    forName: Notification.Name(SystemDeviceLockSignal.lockStateName), object: nil, queue: nil, using: latch)),
                (workspace, workspace.addObserver(
                    forName: NSWorkspace.willSleepNotification, object: nil, queue: nil, using: latch)),
                (workspace, workspace.addObserver(
                    forName: NSWorkspace.sessionDidResignActiveNotification, object: nil, queue: nil, using: latch)),
            ]
        }

        deinit {
            for (center, observer) in observers { center.removeObserver(observer) }
        }

        func changed() -> Bool { latched.withLock { $0 } }
    }
    #endif
}

/// The posts of one Darwin notification since this object was made, read as a counter: `changed`
/// is true once any was posted, whether or not the process ran meanwhile.
final class DarwinNotifyWatch: DeviceLockWatch {
    private let token: Int32
    private let latched = Mutex(false)

    /// Nil when the system refuses the registration.
    init?(name: String) {
        var token: Int32 = 0
        guard Self.ok(notify_register_check(name, &token)) else { return nil }
        // The first check of a new token always says "posted": used up here.
        var first: Int32 = 0
        guard Self.ok(notify_check(token, &first)) else {
            notify_cancel(token)
            return nil
        }
        self.token = token
    }

    deinit {
        notify_cancel(token)
    }

    func changed() -> Bool {
        latched.withLock { latched in
            if latched { return true }
            var posted: Int32 = 0
            // An error is read as a lock: the window ends.
            if !Self.ok(notify_check(token, &posted)) || posted != 0 { latched = true }
            return latched
        }
    }

    private static func ok(_ status: UInt32) -> Bool { status == UInt32(NOTIFY_STATUS_OK) }
}
