import SwiftUI

// DBGlass: thin wrappers that make the right Liquid Glass choice the easy one.
//
// Do:
// - Glass on the control layer that floats above content: floating buttons,
//   toasts, custom bottom bars (UX-GLASS-01). System bars, tab bars, toolbars
//   and sheets already get glass; leave them alone and delete custom bar
//   backgrounds, blurs and shadows (UX-GLASS-05).
// - Group nearby glass controls in one `DBGlassGroup` so they blend and morph
//   instead of stacking (UX-GLASS-02).
// - `.regular` by default; `.clear` only over rich media such as photos, maps
//   or video, with bold foreground (UX-GLASS-03).
// - Tint only the one primary action: `dbPrimaryAction()` (UX-GLASS-04, UX-ACT-01).
// - Text on glass: 15 pt regular or larger, checked with Reduce Transparency
//   and Increase Contrast (UX-GLASS-07). System glass falls back by itself.
//
// Don't:
// - Glass on content: list rows, cards, feed items, charts, text blocks.
// - Glass on glass.
// - A custom search field. The native `TabView` with `Tab(role: .search)` is
//   the only search entry (UX-GLASS-08):
//
//       TabView {
//           Tab("Home", systemImage: "house") { HomeView() }
//           Tab(role: .search) { SearchView().searchable(text: $query) }
//       }

/// Which glass to use. `.regular` almost always.
public enum DBGlassVariant: Sendable, Hashable {
    case regular
    /// Over photos, maps or video only, with bold foreground.
    case clearOverMedia
}

public extension View {
    /// Liquid Glass for a floating control, in a capsule. Never use it on content.
    func dbFloatingGlass(
        _ variant: DBGlassVariant = .regular,
        interactive: Bool = true,
        tint: Color? = nil
    ) -> some View {
        dbFloatingGlass(variant, in: Capsule(), interactive: interactive, tint: tint)
    }

    /// Liquid Glass for a floating control, in `shape`. Never use it on content.
    func dbFloatingGlass<S: Shape>(
        _ variant: DBGlassVariant = .regular,
        in shape: S,
        interactive: Bool = true,
        tint: Color? = nil
    ) -> some View {
        #if os(visionOS)
        // visionOS has no Liquid Glass: its own glass material.
        return background(.regularMaterial, in: shape)
        #else
        var glass: Glass = variant == .clearOverMedia ? .clear : .regular
        if let tint {
            glass = glass.tint(tint)
        }
        if interactive {
            glass = glass.interactive()
        }
        return glassEffect(glass, in: shape)
        #endif
    }

    /// The one prominent action of a screen (UX-ACT-01, UX-GLASS-04).
    /// For floating controls; a primary button inside content uses `.borderedProminent`.
    @ViewBuilder func dbPrimaryAction() -> some View {
        #if os(visionOS)
        buttonStyle(.borderedProminent)
        #else
        buttonStyle(.glassProminent)
        #endif
    }

    /// A secondary floating action.
    @ViewBuilder func dbSecondaryAction() -> some View {
        #if os(visionOS)
        buttonStyle(.bordered)
        #else
        buttonStyle(.glass)
        #endif
    }
}

/// Groups nearby glass controls so they render as one layer and can morph
/// into each other (UX-GLASS-02). Wraps `GlassEffectContainer`.
public struct DBGlassGroup<Content: View>: View {
    private let spacing: CGFloat?
    private let content: Content

    /// - Parameter spacing: Distance under which shapes start to blend.
    public init(spacing: CGFloat? = nil, @ViewBuilder content: () -> Content) {
        self.spacing = spacing
        self.content = content()
    }

    public var body: some View {
        #if os(visionOS)
        content
        #else
        GlassEffectContainer(spacing: spacing) {
            content
        }
        #endif
    }
}
