#if os(iOS)
import SwiftUI

/// Motion shared by the iPhone app and the AutoFill sheet. One house style: critically damped
/// springs (no overshoot, interruptible, they retarget from the current value), short. With Reduce
/// Motion on, movement gives way to a short fade; feedback stays.
public enum Motion {
    /// A fold opening or closing, content swapping in a sheet: about 0.3 s, no bounce.
    public static func fold(reduceMotion: Bool) -> Animation {
        reduceMotion ? .easeOut(duration: 0.2) : .spring(duration: 0.3, bounce: 0)
    }

    /// Rows appearing or leaving a list after a data change (favorite, trash, new item).
    public static func list(reduceMotion: Bool) -> Animation {
        reduceMotion ? .easeOut(duration: 0.2) : .spring(duration: 0.35, bounce: 0)
    }

    /// Content revealed by a fold: fades in while settling down a few points from under its
    /// header, and simply fades out (the exit is the system answering, it stays quick).
    public static func reveal(reduceMotion: Bool) -> AnyTransition {
        reduceMotion
            ? .opacity
            : .asymmetric(insertion: .opacity.combined(with: .offset(y: -8)), removal: .opacity)
    }

    /// How long a "copied" check stays before the control returns to its usual symbol.
    public static let copiedHold: Duration = .milliseconds(1400)
}

/// Any card or tile that acts as a button: shrinks to 97% the moment the finger lands, springs back
/// on release. With Reduce Motion the card dims instead of moving.
public struct PressableButtonStyle: ButtonStyle {
    private let scale: CGFloat

    public init(scale: CGFloat = 0.97) {
        self.scale = scale
    }

    public func makeBody(configuration: Configuration) -> some View {
        PressableBody(configuration: configuration, scale: scale)
    }
}

private struct PressableBody: View {
    @Environment(\.isEnabled) private var isEnabled
    let configuration: ButtonStyleConfiguration
    let scale: CGFloat

    var body: some View {
        configuration.label
            .pressedAppearance(configuration.isPressed && isEnabled, scale: scale)
    }
}

/// A row inside a card: highlighted the instant it is touched, the highlight fading on release, as
/// a list row.
public struct RowHighlightButtonStyle: ButtonStyle {
    public init() {}

    public func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .background(Color.primary.opacity(configuration.isPressed ? 0.08 : 0))
            .animation(configuration.isPressed ? nil : .easeOut(duration: 0.2), value: configuration.isPressed)
            .contentShape(.rect)
    }
}

/// Reports a button's pressed state to its owner: a card whose tap target is an overlay link still
/// shrinks as one piece.
public struct PressReportingButtonStyle: ButtonStyle {
    @Binding private var isPressed: Bool

    public init(isPressed: Binding<Bool>) {
        _isPressed = isPressed
    }

    public func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .onChange(of: configuration.isPressed, initial: false) { _, pressed in isPressed = pressed }
    }
}

extension View {
    /// The pressed look of `PressableButtonStyle`, for a view that receives its pressed state from
    /// elsewhere (`PressReportingButtonStyle`).
    public func pressedAppearance(_ pressed: Bool, scale: CGFloat = 0.97) -> some View {
        modifier(PressedAppearance(pressed: pressed, scale: scale))
    }
}

private struct PressedAppearance: ViewModifier {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let pressed: Bool
    let scale: CGFloat

    func body(content: Content) -> some View {
        content
            .scaleEffect(pressed && !reduceMotion ? scale : 1)
            .opacity(pressed && reduceMotion ? 0.7 : 1)
            // Down is quick (the finger is waiting for an answer), the release settles a little longer.
            .animation(.spring(duration: pressed ? 0.12 : 0.25, bounce: 0), value: pressed)
    }
}
#endif
