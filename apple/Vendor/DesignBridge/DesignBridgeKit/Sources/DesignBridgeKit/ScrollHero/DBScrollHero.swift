import SwiftUI

/// The pure geometry of `DBScrollHero` (UX-SCROLL-03), separate for tests.
public struct DBScrollHeroMetrics: Sendable, Equatable {
    /// Allowed parallax factors: the backdrop moves at 0.3 to 0.5x the scroll.
    public static let parallaxRange: ClosedRange<CGFloat> = 0.3...0.5
    /// Header scale once fully covered.
    public static let minimumHeaderScale: CGFloat = 0.9
    /// Default anchor of the header's scale: bottom centre, so a centred header
    /// shrinks in place instead of drifting sideways.
    public static let defaultHeaderAnchor: UnitPoint = .bottom

    /// Scroll offset, 0 at rest, negative while pulling down.
    public var offset: CGFloat
    public var heroHeight: CGFloat
    /// Distance over which the header fades out.
    public var fadeDistance: CGFloat
    /// nil turns parallax off.
    public var parallax: CGFloat?
    public var reduceMotion: Bool

    public init(offset: CGFloat, heroHeight: CGFloat, fadeDistance: CGFloat, parallax: CGFloat?, reduceMotion: Bool) {
        self.offset = offset
        self.heroHeight = heroHeight
        self.fadeDistance = max(1, fadeDistance)
        self.parallax = parallax.map { $0.clamped(to: Self.parallaxRange) }
        self.reduceMotion = reduceMotion
    }

    /// 0 at rest, 1 once the header has faded out.
    public var progress: CGFloat {
        (offset / fadeDistance).clamped(to: 0...1)
    }

    public var headerOpacity: Double {
        Double(1 - progress)
    }

    /// Scales from 1 to 0.9; stays at 1 under Reduce Motion, where only opacity changes.
    public var headerScale: CGFloat {
        reduceMotion ? 1 : 1 - (1 - Self.minimumHeaderScale) * progress
    }

    /// Keeps the header pinned in place while the sheet slides over it. On
    /// pull-down (negative offset) it is 0, so the header rides down with the
    /// content and the gap above the sheet never grows.
    public var headerOffset: CGFloat {
        max(offset, 0)
    }

    /// Moves the backdrop up at the parallax factor; still under Reduce Motion.
    public var backdropOffset: CGFloat {
        guard !reduceMotion, let parallax, offset > 0 else { return 0 }
        return -offset * parallax
    }

    /// Stretches the backdrop on pull-down; never under Reduce Motion.
    public var backdropScale: CGFloat {
        guard !reduceMotion, offset < 0, heroHeight > 0 else { return 1 }
        return 1 + (-offset / heroHeight)
    }
}

/// A fixed backdrop with a sheet that scrolls over it. The header content
/// stays pinned and fades and scales out as the sheet covers it; the backdrop
/// moves at 0.3 to 0.5x the scroll and stretches on pull-down. Under Reduce
/// Motion the backdrop holds still and the header only crossfades.
///
/// ```swift
/// DBScrollHero(heroHeight: 320) {
///     Image(.cover).resizable().scaledToFill()
/// } header: {
///     Text("Lisbon").font(.largeTitle.bold())
/// } content: {
///     TripDetails()
/// }
/// ```
public struct DBScrollHero<Backdrop: View, Header: View, Content: View>: View {
    private let fixedHeroHeight: CGFloat?
    private let fadeDistance: CGFloat?
    private let position: Binding<ScrollPosition>?
    private let parallax: CGFloat?
    private let headerAnchor: UnitPoint
    private let backdrop: Backdrop
    private let header: Header
    private let content: Content

    @Environment(\.dbTheme) private var theme
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var geometry = HeroGeometry()
    /// The header's own height, used when no fixed hero height is given.
    @State private var measuredHeader: CGFloat = 0

    /// - Parameters:
    ///   - heroHeight: Height of the area above the sheet at rest. nil sizes it to the header, so
    ///     a header that grows with Dynamic Type never slides under the sheet.
    ///   - fadeDistance: Scroll distance over which the header fades; defaults to 60% of `heroHeight`.
    ///   - parallax: Backdrop speed, clamped to 0.3 to 0.5. nil keeps the backdrop fixed.
    ///   - position: Optional scroll position, to start scrolled (captures) or scroll to the top.
    ///   - headerAnchor: Anchor of the header's scale-out. Bottom centre by default; pass
    ///     `.bottomLeading` for a leading-aligned header.
    public init(
        heroHeight: CGFloat? = 320,
        fadeDistance: CGFloat? = nil,
        parallax: CGFloat? = 0.4,
        position: Binding<ScrollPosition>? = nil,
        headerAnchor: UnitPoint = DBScrollHeroMetrics.defaultHeaderAnchor,
        @ViewBuilder backdrop: () -> Backdrop,
        @ViewBuilder header: () -> Header,
        @ViewBuilder content: () -> Content
    ) {
        self.fixedHeroHeight = heroHeight
        self.fadeDistance = fadeDistance
        self.parallax = parallax
        self.position = position
        self.headerAnchor = headerAnchor
        self.backdrop = backdrop()
        self.header = header()
        self.content = content()
    }

    private var heroHeight: CGFloat {
        fixedHeroHeight ?? measuredHeader
    }

    private var metrics: DBScrollHeroMetrics {
        DBScrollHeroMetrics(
            offset: geometry.offset,
            heroHeight: heroHeight,
            fadeDistance: fadeDistance ?? heroHeight * 0.6,
            parallax: parallax,
            reduceMotion: reduceMotion
        )
    }

    public var body: some View {
        let metrics = metrics
        let radius = theme.sheetCornerRadius
        ScrollView {
            VStack(spacing: 0) {
                header
                    .frame(maxWidth: .infinity, minHeight: fixedHeroHeight, alignment: .bottomLeading)
                    .padding(.horizontal, theme.spacing.l)
                    .padding(.bottom, theme.spacing.xl)
                    .onGeometryChange(for: CGFloat.self) { $0.size.height } action: { measuredHeader = $0 }
                    .scaleEffect(metrics.headerScale, anchor: headerAnchor)
                    .opacity(metrics.headerOpacity)
                    .offset(y: metrics.headerOffset)
                    .accessibilityHidden(metrics.headerOpacity < 0.05)
                // Drawn after the header, so the sheet covers it.
                content
                    .frame(maxWidth: .infinity, alignment: .top)
                    .frame(minHeight: max(0, geometry.containerHeight - radius), alignment: .top)
                    .background(
                        theme.sheetBackground,
                        in: UnevenRoundedRectangle(topLeadingRadius: radius, topTrailingRadius: radius, style: .continuous)
                    )
            }
        }
        .modifier(OptionalScrollPosition(position: position))
        .background(alignment: .top) {
            backdrop
                .frame(maxWidth: .infinity)
                .frame(height: heroHeight + geometry.topInset + radius)
                .clipped()
                .scaleEffect(metrics.backdropScale, anchor: .top)
                .offset(y: metrics.backdropOffset)
                .ignoresSafeArea(edges: .top)
                .accessibilityHidden(true)
        }
        .background(theme.sheetBackground.ignoresSafeArea())
        .onScrollGeometryChange(for: HeroGeometry.self) { scroll in
            HeroGeometry(
                offset: scroll.contentOffset.y + scroll.contentInsets.top,
                containerHeight: scroll.containerSize.height,
                topInset: scroll.contentInsets.top
            )
        } action: { _, new in
            geometry = new
        }
    }
}

private struct OptionalScrollPosition: ViewModifier {
    let position: Binding<ScrollPosition>?

    func body(content: Content) -> some View {
        if let position { content.scrollPosition(position) } else { content }
    }
}

private struct HeroGeometry: Equatable {
    var offset: CGFloat = 0
    var containerHeight: CGFloat = 0
    var topInset: CGFloat = 0
}
