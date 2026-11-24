import CoreGraphics

/// How one value reached the field, in the order they are tried (spec, Fill strategies). The raw
/// value names the strategy in the log.
public enum FillStrategy: String, Sendable, CaseIterable {
    case accessibility, typing, clipboard
}

/// What happened to the last strategy tried for one value.
public enum StrategyResult: Equatable, Sendable {
    /// Nothing tried yet.
    case start
    case worked(FillStrategy)
    case failed(FillStrategy)
}

/// The secure keyboard input session (`IsSecureEventInputEnabled`) and its owner when known.
public enum SecureInput: Equatable, Sendable {
    case off
    case owned(by: Int32)
    /// On, with no owner the helper could read.
    case ownerUnknown
}

/// The helper's choices around a fill, kept pure so they can be tested without Accessibility.
public enum FillDecision {
    /// Keys typed between two focus guard checks.
    public static let keysPerBatch = 8

    /// The strategy after `result`: accessibility, then typing, then the clipboard, then none.
    /// A strategy that worked ends the chain. `typingBlocked` skips typing (secure input owned by
    /// another process: keystrokes would go nowhere).
    public static func next(after result: StrategyResult, typingBlocked: Bool = false) -> FillStrategy? {
        switch result {
        case .start: return .accessibility
        case .worked: return nil
        case .failed(.accessibility): return typingBlocked ? .clipboard : .typing
        case .failed(.typing): return .clipboard
        case .failed(.clipboard): return nil
        }
    }

    /// Typing never starts while a secure input session belongs to another process than the
    /// target. An owner the helper cannot read counts as another process.
    public static func secureInputBlocksTyping(_ secureInput: SecureInput, targetPID: Int32) -> Bool {
        switch secureInput {
        case .off: false
        case .owned(let pid): pid != targetPID
        case .ownerUnknown: true
        }
    }

    /// The index ranges of `count` keys, `keysPerBatch` at a time.
    public static func batches(of count: Int) -> [Range<Int>] {
        stride(from: 0, to: max(count, 0), by: keysPerBatch).map { $0..<min($0 + keysPerBatch, count) }
    }
}

/// Accessibility frames are in global coordinates with the origin at the top left of the main
/// screen and y going down; AppKit's are from the bottom left of the main screen, y going up.
/// Both spaces span every screen, so one flip around the main screen's height converts any
/// screen's frame.
public enum ScreenGeometry {
    /// `rect` from Accessibility (`AXFrame`) to AppKit screen coordinates. `primaryScreenHeight` is
    /// the height of the screen at the AppKit origin (`NSScreen.screens.first`). Its own inverse.
    public static func appKitRect(fromAX rect: CGRect, primaryScreenHeight: CGFloat) -> CGRect {
        CGRect(
            x: rect.origin.x, y: primaryScreenHeight - rect.origin.y - rect.height,
            width: rect.width, height: rect.height)
    }

    /// The pill's origin: inside the field's trailing edge, centred on its height, kept within
    /// `visible` (the visible frame of the field's screen). All in AppKit coordinates.
    public static func pillOrigin(field: CGRect, pill: CGSize, visible: CGRect, inset: CGFloat = 4) -> CGPoint {
        var x = field.maxX - pill.width - inset
        var y = field.midY - pill.height / 2
        x = min(max(x, visible.minX), visible.maxX - pill.width)
        y = min(max(y, visible.minY), visible.maxY - pill.height)
        return CGPoint(x: x, y: y)
    }
}
