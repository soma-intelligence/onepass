import SwiftUI

public extension View {
    /// Hosts toasts for everything below: injects `\.toast` and shows one
    /// Liquid Glass capsule at the top. Put it once, at the root of a window or
    /// of a full-screen cover.
    ///
    /// The default placement keeps the toast below the navigation bar, so it
    /// never covers toolbar buttons (Edit, More) right after a copy (UX-TOAST-03).
    func dbToastHost(placement: DBToastPlacement = .belowNavigationBar) -> some View {
        modifier(DBToastHostModifier(placement: placement))
    }
}

/// Where the toast capsule sits under the top safe area.
public enum DBToastPlacement: Sendable, Equatable {
    /// Right under the status bar. Only for hosts with no navigation bar.
    case top
    /// Under the navigation bar, clear of its toolbar buttons.
    case belowNavigationBar

    /// Standard compact navigation bar height on iPhone and iPad.
    public static let navigationBarHeight: CGFloat = 44
    /// Gap between the bar (or status bar) and the capsule.
    public static let gap: CGFloat = 8

    /// Top padding of the capsule, inside the top safe area.
    /// macOS and visionOS keep toolbars outside the content area, so only the gap applies.
    public var topInset: CGFloat {
        switch self {
        case .top:
            return Self.gap
        case .belowNavigationBar:
            #if os(iOS)
            return Self.navigationBarHeight + Self.gap
            #else
            return Self.gap
            #endif
        }
    }
}

private struct DBToastHostModifier: ViewModifier {
    let placement: DBToastPlacement
    @State private var center = DBToastCenter()

    func body(content: Content) -> some View {
        let center = center
        content
            .environment(\.toast, DBToastPresenter { center.show($0) })
            .overlay(alignment: .top) {
                DBToastOverlay(center: center, placement: placement)
            }
    }
}

private struct DBToastSignal: Equatable {
    let id: UUID
    let kind: DBToastKind
}

private struct DBToastOverlay: View {
    let center: DBToastCenter
    let placement: DBToastPlacement
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        ZStack(alignment: .top) {
            if let toast = center.current {
                DBToastCapsule(toast: toast, center: center)
                    .id(toast.id)
                    .transition(DBMotion.transition(edge: .top, reduceMotion: reduceMotion))
            }
        }
        .frame(maxWidth: .infinity, alignment: .top)
        .padding(.horizontal, 16)
        .padding(.top, placement.topInset)
        .animation(DBSpring.smooth.animation(reduceMotion: reduceMotion), value: center.current?.id)
        .dbHaptic(trigger: center.current.map { DBToastSignal(id: $0.id, kind: $0.kind) }) { _, new in
            new.flatMap { DBHapticEvent.forToast($0.kind) }
        }
    }
}

/// The visible toast: a glass capsule with a glyph, the message and an optional action.
/// Glass is right here because the toast floats above content (UX-GLASS-01).
private struct DBToastCapsule: View {
    let toast: DBToast
    let center: DBToastCenter

    @Environment(\.dbTheme) private var theme
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @AccessibilityFocusState private var isFocused: Bool
    @State private var dragOffset: CGFloat = 0

    private var tint: Color {
        switch toast.kind {
        case .success: theme.success
        case .info: theme.info
        case .error: theme.error
        }
    }

    var body: some View {
        HStack(spacing: theme.spacing.m) {
            Image(systemName: toast.systemImage)
                .foregroundStyle(tint)
                .accessibilityHidden(true)
            Text(toast.message)
                .font(theme.toastFont)
                .foregroundStyle(theme.textPrimary)
                .dbText(maxLines: 3)
                .accessibilityFocused($isFocused)
            if let action = toast.action {
                Button {
                    action.handler()
                    center.dismiss()
                } label: {
                    Text(action.title)
                        .font(theme.toastFont)
                        .foregroundStyle(theme.accent)
                        .frame(minWidth: 44, minHeight: 44)
                }
                .buttonStyle(.dbPress)
            }
        }
        .padding(.horizontal, theme.spacing.l)
        .padding(.vertical, theme.spacing.s)
        .frame(minHeight: 48)
        .dbFloatingGlass(interactive: false)
        .frame(maxWidth: 520)
        .offset(y: dragOffset)
        .gesture(swipeToDismiss)
        .accessibilityElement(children: .contain)
        // The UI test contract: DBUITestCase.assertToast looks for this identifier.
        .accessibilityIdentifier(DBToast.accessibilityIdentifier)
        .accessibilityAction(named: Text(DBStrings.dismiss)) { center.dismiss() }
        .onChange(of: isFocused) { _, focused in
            focused ? center.pause(.voiceOver) : center.resume(.voiceOver)
        }
    }

    private var swipeToDismiss: some Gesture {
        DragGesture(minimumDistance: 6)
            .onChanged { value in
                center.pause(.touch)
                let dy = value.translation.height
                // Free upward, rubber band downward.
                dragOffset = dy < 0 ? dy : dy * 0.2
            }
            .onEnded { value in
                let flung = value.predictedEndTranslation.height < -60
                if value.translation.height < -24 || flung {
                    center.dismiss()
                } else {
                    withDBAnimation(.snappy, reduceMotion: reduceMotion) { dragOffset = 0 }
                    center.resume(.touch)
                }
            }
    }
}
