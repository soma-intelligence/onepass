import DesignBridgeKit
import SwiftUI

private typealias RX = Theme.RX

// MARK: Frosted Réglages
//
// The shared Réglages look (spec 2026-11-17-settings-frosted-design): the app's wallpaper blurred
// hard behind the whole page, frosted translucent cards (not Liquid Glass: glass stays on the bar
// and controls), monochrome rows without chevrons. The parts are layout and style only: each app
// brings its own rows, plan card and footer lines.

/// The frosted fills, light and dark, and their opaque fallback under Reduce Transparency or
/// Increase Contrast.
public enum RXFrost {
    /// The card fill over the blurred wallpaper.
    public static func cardFill(_ scheme: ColorScheme, flat: Bool) -> Color {
        if flat { return RX.Palette.cardBackground.color }
        return scheme == .dark ? Color.white.opacity(0.09) : Color.white.opacity(0.58)
    }

    /// The veil over the blurred wallpaper: darker in dark mode, lighter in light mode, so the
    /// words keep their contrast whatever the picture.
    static func veil(_ scheme: ColorScheme) -> Color {
        scheme == .dark ? Color.black.opacity(0.42) : Color.white.opacity(0.5)
    }

    /// The corner radius of every frosted card (the page sheet radius, 28).
    public static let radius = RX.Radius.pageSheet
    /// The pitch of a frosted row: taller than a menu row, the reference's airy list.
    public static let rowPitch: CGFloat = 60
    /// The large avatar of the header.
    public static let avatar: CGFloat = 104
    /// The small avatar in the bar once the header has scrolled away.
    public static let compactAvatar: CGFloat = 34
}

/// The frosted backdrop, veiled. With an image: that picture (the app's wallpaper) blurred hard.
/// Without one: a live material that blurs whatever is behind the page, for a full screen cover
/// whose presentation background is clear (the screen it covers shows through, out of focus). Under
/// Reduce Transparency or Increase Contrast: the plain page colour.
public struct RXFrostedBackdrop: View {
    let image: Image?
    @Environment(\.colorScheme) private var scheme
    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    public init(image: Image? = nil) {
        self.image = image
    }

    public var body: some View {
        if Theme.Wash.isFlat(increaseContrast: contrast == .increased, reduceTransparency: reduceTransparency) {
            RX.Palette.pageBackground.color
        } else if let image {
            Color.clear
                .overlay {
                    image
                        .resizable()
                        .scaledToFill()
                        .blur(radius: 70, opaque: true)
                        .scaleEffect(1.2)
                }
                .overlay(RXFrost.veil(scheme))
                .clipped()
                .accessibilityHidden(true)
        } else {
            Rectangle()
                .fill(.ultraThinMaterial)
                .overlay(RXFrost.veil(scheme).opacity(0.6))
                .accessibilityHidden(true)
        }
    }
}

/// A frosted page: one scroll over the blurred wallpaper. The large header scrolls away under a
/// soft blur at the top, and `compact` (a small avatar) fades in at the centre of the bar once it
/// has gone.
public struct RXFrostedPage<Compact: View, Header: View, Content: View>: View {
    let backdrop: Image?
    let compact: Compact
    let header: Header
    let content: Content
    @State private var offset: CGFloat = 0
    @State private var headerHeight: CGFloat = 0

    public init(backdrop: Image? = nil, @ViewBuilder compact: () -> Compact, @ViewBuilder header: () -> Header,
                @ViewBuilder content: () -> Content) {
        self.backdrop = backdrop
        self.compact = compact()
        self.header = header()
        self.content = content()
    }

    private var collapsed: Bool { headerHeight > 0 && offset > headerHeight * 0.55 }

    public var body: some View {
        ScrollView {
            VStack(spacing: RX.Space.l) {
                header
                    .onGeometryChange(for: CGFloat.self) { $0.size.height } action: { headerHeight = $0 }
                    .opacity(headerHeight > 0 ? max(0, 1 - offset / max(headerHeight * 0.8, 1)) : 1)
                content
            }
            .padding(.horizontal, RX.Space.gutter)
            .padding(.bottom, RX.Space.xxl)
        }
        .onScrollGeometryChange(for: CGFloat.self) { $0.contentOffset.y + $0.contentInsets.top } action: { _, new in
            offset = new
        }
        .modifier(RXPullDownToDismiss())
        .background(RXFrostedBackdrop(image: backdrop).ignoresSafeArea())
        #if os(iOS)
        // The navigation stack paints no colour of its own: the backdrop (or the screen under a
        // clear full screen cover) shows.
        .containerBackground(Color.clear, for: .navigation)
        #endif
        .overlay(alignment: .top) { TopBlur(visible: offset > 4) }
        #if os(iOS)
        .toolbarBackground(.hidden, for: .navigationBar)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .principal) {
                compact
                    .opacity(collapsed ? 1 : 0)
                    .scaleEffect(collapsed ? 1 : 0.8)
                    .animation(.smooth(duration: 0.25), value: collapsed)
                    .accessibilityHidden(!collapsed)
            }
            .sharedBackgroundVisibility(.hidden)
        }
        #endif
    }
}

/// The soft blur under the bar: content scrolling up goes out of focus before it reaches the
/// buttons.
private struct TopBlur: View {
    let visible: Bool

    var body: some View {
        GeometryReader { proxy in
            Rectangle()
                .fill(.ultraThinMaterial)
                .mask(LinearGradient(
                    stops: [.init(color: .black, location: 0), .init(color: .black, location: 0.55),
                            .init(color: .clear, location: 1)],
                    startPoint: .top, endPoint: .bottom))
                .frame(height: proxy.safeAreaInsets.top + 56)
                .ignoresSafeArea(edges: .top)
        }
        .opacity(visible ? 1 : 0)
        .animation(.smooth(duration: 0.2), value: visible)
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }
}

/// The large header: the avatar centred, the name big and bold. Pass the avatar view at
/// `RXFrost.avatar`.
public struct RXFrostedProfileName<Avatar: View>: View {
    let name: Text
    let avatar: Avatar

    public init(_ name: Text, @ViewBuilder avatar: () -> Avatar) {
        self.name = name
        self.avatar = avatar()
    }

    public var body: some View {
        VStack(spacing: RX.Space.m) {
            avatar
            name
                .font(RX.Typography.display.font(size: 34))
                .fontWeight(.bold)
                .tracking(-0.6)
                .foregroundStyle(RX.Palette.textPrimary.color)
                .multilineTextAlignment(.center)
                .dbText(maxLines: 2, minimumScale: 0.7)
        }
        .frame(maxWidth: .infinity)
        .contentShape(Rectangle())
    }
}

/// The line under the name (a handle, the device mode), with an optional small glyph after it.
public struct RXFrostedProfileDetail: View {
    let text: Text
    let systemImage: String?

    public init(_ text: Text, systemImage: String? = nil) {
        self.text = text
        self.systemImage = systemImage
    }

    public var body: some View {
        HStack(spacing: RX.Space.xs) {
            text
            if let systemImage {
                Image(systemName: systemImage)
                    .accessibilityHidden(true)
            }
        }
        .rxFont(.callout)
        .foregroundStyle(RX.Palette.textSecondary.color)
        .padding(.bottom, RX.Space.l)
        .frame(minHeight: RX.Metrics.minTapTarget)
    }
}

/// A frosted card: rows on a translucent fill, 28 pt continuous corners.
public struct RXFrostedCard<Content: View>: View {
    let content: Content
    @Environment(\.colorScheme) private var scheme
    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    public init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    public var body: some View {
        let shape = RoundedRectangle(cornerRadius: RXFrost.radius, style: .continuous)
        let flat = Theme.Wash.isFlat(increaseContrast: contrast == .increased, reduceTransparency: reduceTransparency)
        VStack(alignment: .leading, spacing: 0) {
            content
        }
        .padding(.vertical, RX.Space.s)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RXFrost.cardFill(scheme, flat: flat), in: shape)
        .clipShape(shape)
    }
}

/// A frosted row: a monochrome glyph without a tile, the title, an optional subtitle and an
/// optional count badge. No chevron, no separator. `tint` colours glyph and title (a destructive
/// row passes the negative token).
public struct RXFrostedRow: View {
    let title: Text
    let systemImage: String
    let subtitle: Text?
    let value: Text?
    let badge: Int?
    let tint: Color?

    public init(_ title: Text, systemImage: String, subtitle: Text? = nil, value: Text? = nil, badge: Int? = nil,
                tint: Color? = nil) {
        self.title = title
        self.systemImage = systemImage
        self.subtitle = subtitle
        self.value = value
        self.badge = badge
        self.tint = tint
    }

    public var body: some View {
        let ink = tint ?? RX.Palette.textPrimary.color
        HStack(spacing: RX.Space.l) {
            Image(systemName: systemImage)
                .font(RX.Glyph.font(22, weight: .semibold))
                .foregroundStyle(ink)
                .frame(width: 28, height: 28)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: RX.Space.xxs) {
                title
                    .rxFont(.body)
                    .foregroundStyle(ink)
                    .dbText(maxLines: 2)
                if let subtitle {
                    subtitle
                        .rxFont(.callout)
                        .foregroundStyle(RX.Palette.textSecondary.color)
                        .dbText(maxLines: 2)
                }
            }
            Spacer(minLength: RX.Space.s)
            if let value {
                value
                    .rxFont(.body)
                    .foregroundStyle(RX.Palette.textSecondary.color)
                    .dbText(maxLines: 1)
            }
            if let badge, badge > 0 {
                Text(badge, format: .number)
                    .rxFont(.footnoteBold)
                    .monospacedDigit()
                    .foregroundStyle(RX.Palette.pageBackground.color)
                    .padding(.horizontal, RX.Space.s)
                    .frame(minWidth: 26, minHeight: 26)
                    .background(RX.Palette.textPrimary.color, in: Capsule())
            }
        }
        .padding(.horizontal, RX.Space.l)
        .padding(.vertical, RX.Space.m)
        .frame(minHeight: RXFrost.rowPitch)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
    }
}

/// The small centred lines at the bottom of the page (name and version, publisher, last activity).
public struct RXFrostedFooter: View {
    let lines: [Text]

    public init(_ lines: [Text]) {
        self.lines = lines
    }

    public var body: some View {
        VStack(spacing: RX.Space.xxs) {
            ForEach(lines.indices, id: \.self) { lines[$0] }
        }
        .rxFont(.footnote)
        .foregroundStyle(RX.Palette.textTertiary.color)
        .multilineTextAlignment(.center)
        .frame(maxWidth: .infinity)
        .padding(.top, RX.Space.l)
    }
}

/// The Form pages of a frosted Réglages: the blurred wallpaper behind, frosted row fills. Apply to
/// each `Section` (or the rows) for the fill, and `rxFrostedFormPage` to the Form.
public struct RXFrostedRowFill: ViewModifier {
    @Environment(\.colorScheme) private var scheme
    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    public init() {}

    public func body(content: Content) -> some View {
        content.listRowBackground(RXFrost.cardFill(
            scheme, flat: Theme.Wash.isFlat(increaseContrast: contrast == .increased,
                                            reduceTransparency: reduceTransparency)))
    }
}

// MARK: Pull down to close

public extension EnvironmentValues {
    /// Closes the frosted Réglages when a page is pulled down past its top. Set by the screen that
    /// presents them (a full screen cover has no drag to dismiss of its own); nil elsewhere, where
    /// pulling down only bounces.
    @Entry var rxPullDownDismiss: (() -> Void)? = nil
}

/// Pull down to close: on a scroll view at its top, pulled down past `threshold` and let go, the
/// presenting screen's `rxPullDownDismiss` runs. A light tap of the haptics marks the threshold.
/// The close button stays: this only adds the gesture of a sheet back to a full screen cover.
public struct RXPullDownToDismiss: ViewModifier {
    @Environment(\.rxPullDownDismiss) private var dismiss
    @State private var armed = false

    /// How far past the top the page has to be pulled.
    public static let threshold: CGFloat = 72

    public init() {}

    public func body(content: Content) -> some View {
        #if os(iOS)
        content
            .onScrollGeometryChange(for: Bool.self) {
                -($0.contentOffset.y + $0.contentInsets.top) > Self.threshold
            } action: { _, past in
                armed = past
            }
            .onScrollPhaseChange { old, new in
                if old == .interacting, new != .interacting, armed, let dismiss {
                    armed = false
                    dismiss()
                }
            }
            .sensoryFeedback(.impact(weight: .light), trigger: armed) { _, now in now && dismiss != nil }
        #else
        content
        #endif
    }
}
