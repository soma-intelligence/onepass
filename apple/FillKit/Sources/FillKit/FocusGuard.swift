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

/// What the focus guard compares inside one process: the focused element and its window. Both
/// must match, so a fill never goes into another window of the same app; with no element exposed
/// (a canvas that gives none) the window alone still pins it. Neither one: nothing to guard, and
/// the helper does not type.
public struct FocusTarget<Element: Hashable>: Hashable {
    public let element: Element?
    public let window: Element?

    public init(element: Element?, window: Element?) {
        self.element = element
        self.window = window
    }

    public var isGuardable: Bool { element != nil || window != nil }
}
