import SwiftUI

/// A named spring token. Durations stay in 0.15 to 0.5 s (UX-MOT-01).
public struct DBSpring: Sendable, Hashable {
    public let name: String
    /// Perceptual duration in seconds.
    public let duration: TimeInterval
    /// 0 for functional UI, 0.15 to 0.3 for playful moments.
    public let bounce: Double

    public init(name: String, duration: TimeInterval, bounce: Double) {
        self.name = name
        self.duration = duration
        self.bounce = bounce
    }

    /// The spring itself, ignoring Reduce Motion. Prefer `animation(reduceMotion:)`.
    public var animation: Animation {
        .spring(duration: duration, bounce: bounce)
    }

    /// The spring, or the crossfade fallback under Reduce Motion (UX-MOT-03).
    public func animation(reduceMotion: Bool) -> Animation {
        reduceMotion ? DBMotion.crossfade : animation
    }

    /// Micro interactions: press, toggle, selection. 0.25 s, no bounce.
    public static let snappy = DBSpring(name: "snappy", duration: 0.25, bounce: 0)
    /// Components: toasts, expand and collapse, number rolls. 0.4 s, no bounce.
    public static let smooth = DBSpring(name: "smooth", duration: 0.4, bounce: 0)
    /// Playful or celebratory moments only. 0.45 s, bounce 0.25.
    public static let bouncy = DBSpring(name: "bouncy", duration: 0.45, bounce: 0.25)

    public static let all: [DBSpring] = [.snappy, .smooth, .bouncy]
}

/// Motion constants shared by every primitive.
public enum DBMotion {
    /// Duration of the Reduce Motion crossfade.
    public static let crossfadeDuration: TimeInterval = 0.2
    /// The animation used instead of movement under Reduce Motion.
    public static var crossfade: Animation { .easeInOut(duration: crossfadeDuration) }
    /// The one spring every `DBNumber` uses (UX-NUM-01).
    public static let number: DBSpring = .smooth
    /// Press feedback scale (UX-PRESS-01).
    public static let pressScale: CGFloat = 0.97
    /// Opacity used as press feedback under Reduce Motion, where scaling is dropped.
    public static let pressOpacityReduced: Double = 0.8
    /// Opacity of a disabled control (UX-PRESS-03).
    public static let disabledOpacity: Double = 0.4

    /// An edge transition: move plus opacity, or opacity only under Reduce Motion.
    /// Removal is faster than insertion through the spring (UX-MOT-04).
    public static func transition(edge: Edge, reduceMotion: Bool) -> AnyTransition {
        if reduceMotion {
            return .opacity
        }
        return .asymmetric(
            insertion: .move(edge: edge).combined(with: .opacity),
            removal: .move(edge: edge).combined(with: .opacity)
        )
    }
}

/// `withAnimation` with a DesignBridgeKit spring and the Reduce Motion fallback.
@MainActor
public func withDBAnimation<Result>(
    _ spring: DBSpring = .smooth,
    reduceMotion: Bool,
    _ body: () throws -> Result
) rethrows -> Result {
    try withAnimation(spring.animation(reduceMotion: reduceMotion), body)
}

// MARK: - Modifiers

private struct DBAnimationModifier<V: Equatable>: ViewModifier {
    let spring: DBSpring
    let value: V
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func body(content: Content) -> some View {
        content.animation(spring.animation(reduceMotion: reduceMotion), value: value)
    }
}

private struct DBTransitionModifier: ViewModifier {
    let edge: Edge
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func body(content: Content) -> some View {
        content.transition(DBMotion.transition(edge: edge, reduceMotion: reduceMotion))
    }
}

public extension View {
    /// Animates changes of `value` with a spring token, crossfading under Reduce Motion.
    func dbAnimation<V: Equatable>(_ spring: DBSpring = .smooth, value: V) -> some View {
        modifier(DBAnimationModifier(spring: spring, value: value))
    }

    /// Moves in from `edge`, or fades under Reduce Motion.
    func dbTransition(edge: Edge) -> some View {
        modifier(DBTransitionModifier(edge: edge))
    }
}

// MARK: - Press

/// Scales to 0.97 while pressed and springs back (UX-PRESS-01). Under Reduce
/// Motion it dims instead of scaling. A disabled button neither scales nor
/// dims on press and draws at `DBMotion.disabledOpacity`. Use it on plain
/// `Button`s, never on `onTapGesture` views (UX-PRESS-02).
public struct DBPressButtonStyle: ButtonStyle {
    public init() {}

    public func makeBody(configuration: Configuration) -> some View {
        DBPressBody(configuration: configuration)
    }
}

private struct DBPressBody: View {
    let configuration: ButtonStyleConfiguration
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.isEnabled) private var isEnabled

    var body: some View {
        let pressed = configuration.isPressed && isEnabled
        configuration.label
            .contentShape(.rect)
            .scaleEffect(DBPressMetrics.scale(pressed: pressed, reduceMotion: reduceMotion))
            .opacity(DBPressMetrics.opacity(pressed: pressed, reduceMotion: reduceMotion, isEnabled: isEnabled))
            .animation(DBSpring.snappy.animation(reduceMotion: reduceMotion), value: pressed)
            .animation(DBSpring.snappy.animation(reduceMotion: reduceMotion), value: isEnabled)
    }
}

/// The press style's numbers, split out so they can be tested without a view.
public enum DBPressMetrics {
    public static func scale(pressed: Bool, reduceMotion: Bool) -> CGFloat {
        pressed && !reduceMotion ? DBMotion.pressScale : 1
    }

    public static func opacity(pressed: Bool, reduceMotion: Bool, isEnabled: Bool) -> Double {
        guard isEnabled else { return DBMotion.disabledOpacity }
        return pressed && reduceMotion ? DBMotion.pressOpacityReduced : 1
    }
}

public extension ButtonStyle where Self == DBPressButtonStyle {
    /// `Button { } label: { }.buttonStyle(.dbPress)`
    static var dbPress: DBPressButtonStyle { DBPressButtonStyle() }
}

// MARK: - Zoom navigation

public extension View {
    /// Marks a card as the source of a zoom navigation transition (UX-NAV-01).
    /// Pair with `dbZoomDestination(sourceID:in:)` on the pushed view.
    func dbZoomSource<ID: Hashable>(id: ID, in namespace: Namespace.ID) -> some View {
        matchedTransitionSource(id: id, in: namespace)
    }

    /// Zooms the destination out of its source card (UX-NAV-01).
    ///
    /// The zoom is a system navigation transition. It stays interactive (swipe
    /// back keeps working, UX-NAV-03) and the system adapts it for Reduce
    /// Motion; there is no public crossfade `NavigationTransition` to swap in.
    /// On macOS, which has no navigation transitions, this is a no-op.
    @ViewBuilder
    func dbZoomDestination<ID: Hashable>(sourceID: ID, in namespace: Namespace.ID) -> some View {
        #if os(iOS) || os(visionOS)
        navigationTransition(.zoom(sourceID: sourceID, in: namespace))
        #else
        self
        #endif
    }
}
