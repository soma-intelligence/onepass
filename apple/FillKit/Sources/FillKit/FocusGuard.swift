/// Checked before each fill step: the frontmost app and the focused element must still be the
/// ones the user picked for.
// AnyHashable is not Sendable, but the value is immutable and only compared.
public struct FocusGuard: @unchecked Sendable {
    private let pid: Int32
    private let elementID: AnyHashable

    public init(pid: Int32, elementID: AnyHashable) {
        self.pid = pid
        self.elementID = elementID
    }

    public func holds(pid: Int32, elementID: AnyHashable) -> Bool {
        self.pid == pid && self.elementID == elementID
    }
}
