import DesignKit
import SwiftUI

#if os(macOS)
/// The toolbar's main action: white semibold text on an accent capsule (the system prominent style
/// draws as bare text in a toolbar item without shared glass). Dims when disabled.
struct AccentCapsuleButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        AccentBody(configuration: configuration)
    }

    private struct AccentBody: View {
        let configuration: Configuration
        @Environment(\.isEnabled) private var isEnabled
        @State private var hovering = false

        var body: some View {
            configuration.label
                .font(.body.weight(.semibold))
                .foregroundStyle(.white)
                .padding(.horizontal, Theme.Space.l)
                .padding(.vertical, 6)
                .background(Theme.accent.mix(with: .white, by: hovering ? 0.1 : 0), in: .capsule)
                .overlay { Capsule().strokeBorder(.white.opacity(0.14), lineWidth: 0.5) }
                .contentShape(.capsule)
                .opacity(isEnabled ? (configuration.isPressed ? 0.75 : 1) : 0.45)
                .onHover { hovering = $0 }
                .animation(.easeOut(duration: 0.12), value: hovering)
        }
    }
}

/// A toolbar icon button without glass: a secondary glyph in a 30 pt circle that fills softly and
/// brightens under the pointer.
struct QuietIconButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        QuietIconBody(configuration: configuration)
    }

    private struct QuietIconBody: View {
        let configuration: Configuration
        @State private var hovering = false

        var body: some View {
            configuration.label
                .font(.system(size: 14, weight: .medium))
                .foregroundStyle(hovering ? .primary : .secondary)
                .frame(width: 30, height: 30)
                .background(hovering ? AnyShapeStyle(.fill.tertiary) : AnyShapeStyle(.clear), in: Circle())
                .contentShape(Circle())
                .opacity(configuration.isPressed ? 0.6 : 1)
                .onHover { hovering = $0 }
                .animation(.easeOut(duration: 0.12), value: hovering)
        }
    }
}

/// A text-only toolbar button: secondary text that brightens and gets a soft capsule under the
/// pointer, so "Annuler" sits next to the accent "Enregistrer" without competing with it.
struct QuietToolbarButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        QuietBody(configuration: configuration)
    }

    private struct QuietBody: View {
        let configuration: Configuration
        @State private var hovering = false

        var body: some View {
            configuration.label
                .font(.body.weight(.medium))
                .foregroundStyle(hovering ? .primary : .secondary)
                .padding(.horizontal, Theme.Space.m)
                .padding(.vertical, 6)
                .background(hovering ? AnyShapeStyle(.fill.tertiary) : AnyShapeStyle(.clear), in: .capsule)
                .contentShape(.capsule)
                .opacity(configuration.isPressed ? 0.6 : 1)
                .onHover { hovering = $0 }
                .animation(.easeOut(duration: 0.12), value: hovering)
        }
    }
}
#endif
