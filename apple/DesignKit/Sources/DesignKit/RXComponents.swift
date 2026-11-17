import SwiftUI

// The building blocks of the RX look, one per main component of the Penpot file (page
// "OnePass RX · Components"): glass button, colour disc, item row, menu row, card, quick actions,
// plan card and perk tile. They draw only; the screens wrap them in their own Button,
// NavigationLink, ShareLink or Menu, so the actions stay where they are today.

private typealias RX = Theme.RX

/// The press style of RX controls: the shared shrink on iPhone, plain elsewhere.
private struct RXPressStyle: ViewModifier {
    func body(content: Content) -> some View {
        #if os(iOS)
        content.buttonStyle(PressableButtonStyle())
        #else
        content.buttonStyle(.plain)
        #endif
    }
}

// MARK: Glass

/// The round glass disc behind a glyph: the glass token over a blur on a plain page, white at 18%
/// over a blur on a photo.
public struct RXGlassGlyph: View {
    let systemImage: String
    let diameter: CGFloat
    let glyph: CGFloat?
    let onPhoto: Bool

    public init(systemImage: String, diameter: CGFloat = Theme.RX.Metrics.glassButton, glyph: CGFloat? = nil,
                onPhoto: Bool = false) {
        self.systemImage = systemImage
        self.diameter = diameter
        self.glyph = glyph
        self.onPhoto = onPhoto
    }

    public var body: some View {
        Image(systemName: systemImage)
            .font(.system(size: glyph ?? (diameter * 0.45).rounded(), weight: .semibold))
            .foregroundStyle(onPhoto ? Color.white : RX.Palette.textPrimary.color)
            .frame(width: diameter, height: diameter)
            .rxGlass(in: Circle(), onPhoto: onPhoto)
            .environment(\.colorScheme, onPhoto ? .dark : colorScheme)
            .contentShape(Circle())
    }

    @Environment(\.colorScheme) private var colorScheme
}

/// A round glass button (44 pt), on a plain page or on a photo.
public struct GlassButton: View {
    let systemImage: String
    let label: Text
    let diameter: CGFloat
    let onPhoto: Bool
    let action: () -> Void

    public init(_ label: Text, systemImage: String, diameter: CGFloat = Theme.RX.Metrics.glassButton,
                onPhoto: Bool = false, action: @escaping () -> Void) {
        self.label = label
        self.systemImage = systemImage
        self.diameter = diameter
        self.onPhoto = onPhoto
        self.action = action
    }

    public var body: some View {
        Button(action: action) {
            RXGlassGlyph(systemImage: systemImage, diameter: diameter, onPhoto: onPhoto)
        }
        .modifier(RXPressStyle())
        .accessibilityLabel(label)
    }
}

// MARK: Discs

/// A white glyph on a coloured disc (40 pt by default): the lead of an item row, a stat tile.
public struct ColorDisc: View {
    let systemImage: String
    let color: Color
    let diameter: CGFloat

    public init(systemImage: String, color: Color, diameter: CGFloat = Theme.RX.Metrics.itemLead) {
        self.systemImage = systemImage
        self.color = color
        self.diameter = diameter
    }

    public var body: some View {
        Image(systemName: systemImage)
            .font(.system(size: Theme.RX.Metrics.discGlyph(diameter: diameter) * 0.85, weight: .semibold))
            .foregroundStyle(.white)
            .frame(width: diameter, height: diameter)
            .background(color, in: Circle())
            .accessibilityHidden(true)
    }
}

/// The trailing chevron of a row.
public struct RXChevron: View {
    public init() {}

    public var body: some View {
        Image(systemName: "chevron.right")
            .font(.system(size: 14, weight: .bold))
            .foregroundStyle(RX.Palette.textTertiary.color)
            .accessibilityHidden(true)
    }
}

// MARK: Rows

/// An item row: a 40 pt lead, the title (Body medium) over its subtitle (Callout, secondary), an
/// optional trailing value, an optional chevron. Pitch 64.
public struct RXItemRow<Lead: View>: View {
    let lead: Lead
    let title: Text
    let subtitle: Text?
    let value: Text?
    let valueColor: Color?
    let chevron: Bool

    public init(title: Text, subtitle: Text? = nil, value: Text? = nil, valueColor: Color? = nil,
                chevron: Bool = false, @ViewBuilder lead: () -> Lead) {
        self.lead = lead()
        self.title = title
        self.subtitle = subtitle
        self.value = value
        self.valueColor = valueColor
        self.chevron = chevron
    }

    public var body: some View {
        HStack(spacing: 14) {
            lead
                .frame(width: RX.Metrics.itemLead, height: RX.Metrics.itemLead)
            VStack(alignment: .leading, spacing: 2) {
                title
                    .rxFont(.bodyMedium)
                    .foregroundStyle(RX.Palette.textPrimary.color)
                    .lineLimit(1)
                if let subtitle {
                    subtitle
                        .rxFont(.callout)
                        .foregroundStyle(RX.Palette.textSecondary.color)
                        .lineLimit(1)
                }
            }
            Spacer(minLength: RX.Space.s)
            if let value {
                value
                    .rxFont(.bodyMedium)
                    .monospacedDigit()
                    .foregroundStyle(valueColor ?? RX.Palette.textPrimary.color)
            }
            if chevron { RXChevron() }
        }
        .padding(.vertical, RX.Space.m)
        .padding(.horizontal, RX.Space.l)
        .frame(minHeight: RX.Metrics.itemPitch)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
    }
}

/// A menu row: a 24 pt glyph, the label (Body medium), an optional value and badge, a chevron.
/// Pitch 56. `tint` colours the glyph and label (a destructive row passes the negative token).
public struct RXMenuRow: View {
    let systemImage: String
    let title: Text
    let value: Text?
    let badge: Text?
    let tint: Color?
    let chevron: Bool

    public init(_ title: Text, systemImage: String, value: Text? = nil, badge: Text? = nil, tint: Color? = nil,
                chevron: Bool = true) {
        self.title = title
        self.systemImage = systemImage
        self.value = value
        self.badge = badge
        self.tint = tint
        self.chevron = chevron
    }

    public var body: some View {
        let ink = tint ?? RX.Palette.textPrimary.color
        HStack(spacing: RX.Space.l) {
            Image(systemName: systemImage)
                .font(.system(size: 20, weight: .medium))
                .foregroundStyle(ink)
                .frame(width: RX.Metrics.menuGlyph, height: RX.Metrics.menuGlyph)
                .accessibilityHidden(true)
            title
                .rxFont(.bodyMedium)
                .foregroundStyle(ink)
                .lineLimit(1)
            Spacer(minLength: RX.Space.s)
            if let value {
                value
                    .rxFont(.body)
                    .foregroundStyle(RX.Palette.textSecondary.color)
                    .lineLimit(1)
            }
            if let badge {
                badge
                    .rxFont(.footnoteBold)
                    .foregroundStyle(.white)
                    .padding(.horizontal, RX.Space.s)
                    .frame(minHeight: 22)
                    .background(RX.Palette.accent.color, in: Capsule())
            }
            if chevron { RXChevron() }
        }
        .padding(.horizontal, RX.Space.l)
        .padding(.vertical, RX.Space.m)
        .frame(minHeight: RX.Metrics.menuPitch)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
    }
}

// MARK: Cards

/// A grouped card: the card token, radius 24, 6 pt above and below its rows.
public struct RXCard<Content: View>: View {
    let content: Content

    public init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            content
        }
        .padding(.vertical, 6)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RX.Palette.cardBackground.color, in: RoundedRectangle(cornerRadius: RX.Radius.card, style: .continuous))
        .clipShape(RoundedRectangle(cornerRadius: RX.Radius.card, style: .continuous))
    }
}

/// The title of a card (Headline) with an optional action on the right (Callout medium, accent).
public struct RXCardHeader: View {
    let title: Text
    let actionTitle: Text?
    let action: (() -> Void)?

    public init(_ title: Text, actionTitle: Text? = nil, action: (() -> Void)? = nil) {
        self.title = title
        self.actionTitle = actionTitle
        self.action = action
    }

    public var body: some View {
        HStack {
            title
                .rxFont(.headline)
                .foregroundStyle(RX.Palette.textPrimary.color)
                .accessibilityAddTraits(.isHeader)
            Spacer()
            if let actionTitle, let action {
                Button(action: action) {
                    actionTitle
                        .rxFont(.calloutMedium)
                        .foregroundStyle(RX.Palette.accentText.color)
                }
                .buttonStyle(.plain)
            }
        }
        .padding(EdgeInsets(top: 14, leading: RX.Space.l, bottom: RX.Space.xs, trailing: RX.Space.l))
    }
}

/// A section title between cards (Title).
public struct RXSectionTitle: View {
    let title: Text

    public init(_ title: Text) {
        self.title = title
    }

    public var body: some View {
        title
            .rxFont(.title)
            .foregroundStyle(RX.Palette.textPrimary.color)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(EdgeInsets(top: RX.Space.s, leading: RX.Space.xs, bottom: 0, trailing: RX.Space.xs))
            .accessibilityAddTraits(.isHeader)
    }
}

/// A small tile of the stat row (Watchtower): a disc, the figure (Title), the label (Footnote).
public struct RXStatTile: View {
    let systemImage: String
    let color: Color
    let value: Text
    let label: Text

    public init(value: Text, label: Text, systemImage: String, color: Color) {
        self.value = value
        self.label = label
        self.systemImage = systemImage
        self.color = color
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            ColorDisc(systemImage: systemImage, color: color, diameter: 36)
            value
                .rxFont(.title)
                .monospacedDigit()
                .foregroundStyle(RX.Palette.textPrimary.color)
            label
                .rxFont(.footnote)
                .foregroundStyle(RX.Palette.textSecondary.color)
                .lineLimit(2)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RX.Palette.cardBackground.color, in: RoundedRectangle(cornerRadius: RX.Radius.card, style: .continuous))
        .accessibilityElement(children: .combine)
    }
}

// MARK: Quick actions

/// One quick action: a 48 pt disc over its label (Callout medium). On a page: the raised token and
/// an accent glyph; on a photo: glass and white.
public struct QuickActionLabel: View {
    let systemImage: String
    let title: Text
    let onPhoto: Bool

    public init(_ title: Text, systemImage: String, onPhoto: Bool = false) {
        self.title = title
        self.systemImage = systemImage
        self.onPhoto = onPhoto
    }

    public var body: some View {
        VStack(spacing: RX.Space.s) {
            if onPhoto {
                RXGlassGlyph(systemImage: systemImage, diameter: RX.Metrics.actionDisc, glyph: 20, onPhoto: true)
            } else {
                Image(systemName: systemImage)
                    .font(.system(size: 20, weight: .semibold))
                    .foregroundStyle(RX.Palette.accentText.color)
                    .frame(width: RX.Metrics.actionDisc, height: RX.Metrics.actionDisc)
                    .background(RX.Palette.raisedBackground.color, in: Circle())
                    .shadow(color: .black.opacity(0.06), radius: 5, y: 2)
            }
            title
                .rxFont(.calloutMedium)
                .foregroundStyle(onPhoto ? Color.white : RX.Palette.textPrimary.color)
                .lineLimit(1)
                .minimumScaleFactor(0.8)
        }
        .frame(maxWidth: RX.Metrics.actionWidth)
        .frame(maxWidth: .infinity)
        .contentShape(Rectangle())
    }
}

/// A quick action that runs a closure.
public struct QuickAction: Identifiable {
    public let id: String
    let title: Text
    let systemImage: String
    let action: () -> Void

    public init(id: String, title: Text, systemImage: String, action: @escaping () -> Void) {
        self.id = id
        self.title = title
        self.systemImage = systemImage
        self.action = action
    }
}

/// The row of quick actions (four in the mock), spread over the width.
public struct QuickActionRow<Content: View>: View {
    let content: Content

    /// Free content: `QuickActionLabel`s wrapped in the screen's own Button, ShareLink or Menu.
    public init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    public var body: some View {
        HStack(alignment: .top, spacing: 0) {
            content
        }
        .frame(maxWidth: .infinity)
    }
}

extension QuickActionRow where Content == AnyView {
    /// Plain buttons, one per action.
    public init(_ actions: [QuickAction], onPhoto: Bool = false) {
        self.content = AnyView(
            ForEach(actions) { action in
                Button(action: action.action) {
                    QuickActionLabel(action.title, systemImage: action.systemImage, onPhoto: onPhoto)
                }
                .modifier(RXPressStyle())
                .accessibilityIdentifier("rx.action.\(action.id)")
            })
    }
}

// MARK: Plan card and perks

/// The plan card over the Settings photo: the plan name (Title), "View plan benefits", a row of
/// perk discs on glass, the 3D art on the right. Glass: white at 14% over a blur, a white hairline.
public struct PlanCard: View {
    let title: Text
    let subtitle: Text
    let art: Image?
    let perks: [String]

    /// `perks`: the SF Symbols of the perk discs, left to right.
    public init(title: Text, subtitle: Text, art: Image?, perks: [String]) {
        self.title = title
        self.subtitle = subtitle
        self.art = art
        self.perks = perks
    }

    public var body: some View {
        let shape = RoundedRectangle(cornerRadius: RX.Radius.card, style: .continuous)
        ZStack(alignment: .topLeading) {
            if let art {
                art
                    .resizable()
                    .scaledToFit()
                    .frame(width: 186, height: 124)
                    .frame(maxWidth: .infinity, alignment: .trailing)
                    .padding(.trailing, RX.Space.s)
                    .accessibilityHidden(true)
            }
            VStack(alignment: .leading, spacing: 0) {
                title
                    .rxFont(.title)
                    .foregroundStyle(.white)
                subtitle
                    .rxFont(.body)
                    .foregroundStyle(.white.opacity(0.72))
                Spacer(minLength: RX.Space.s)
                HStack(spacing: RX.Space.s) {
                    ForEach(perks, id: \.self) { symbol in
                        RXGlassGlyph(systemImage: symbol, diameter: 40, glyph: 17, onPhoto: true)
                    }
                }
                .accessibilityHidden(true)
            }
            .padding(EdgeInsets(top: 16, leading: 18, bottom: 16, trailing: 18))
        }
        .frame(maxWidth: .infinity, minHeight: RX.Metrics.planCardHeight, maxHeight: RX.Metrics.planCardHeight,
               alignment: .topLeading)
        .rxGlass(in: shape, onPhoto: true, interactive: false)
        .environment(\.colorScheme, .dark)
        .clipShape(shape)
        .accessibilityElement(children: .combine)
    }
}

/// A perk tile of "Get more from Plus": the art full bleed, a dark scrim at the bottom, a glass glyph,
/// the title (Headline) and one line (Footnote), all white.
public struct PerkTile: View {
    let art: Image
    let title: Text
    let subtitle: Text
    let systemImage: String

    public init(title: Text, subtitle: Text, systemImage: String, art: Image) {
        self.title = title
        self.subtitle = subtitle
        self.systemImage = systemImage
        self.art = art
    }

    public var body: some View {
        let shape = RoundedRectangle(cornerRadius: RX.Radius.perk, style: .continuous)
        ZStack(alignment: .bottomLeading) {
            Color(white: 0.11)
            art
                .resizable()
                .scaledToFill()
                .frame(minWidth: 0, maxWidth: .infinity, minHeight: 0, maxHeight: .infinity)
                .clipped()
                .accessibilityHidden(true)
            LinearGradient(
                stops: [
                    .init(color: .black.opacity(0), location: 0), .init(color: .black.opacity(0.05), location: 0.45),
                    .init(color: .black.opacity(0.75), location: 1),
                ],
                startPoint: .top, endPoint: .bottom)
            VStack(alignment: .leading, spacing: 2) {
                RXGlassGlyph(systemImage: systemImage, diameter: 32, glyph: 15, onPhoto: true)
                    .padding(.bottom, RX.Space.s)
                title
                    .rxFont(.headline)
                    .lineLimit(1)
                    .minimumScaleFactor(0.85)
                subtitle
                    .rxFont(.footnote)
                    .opacity(0.75)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .foregroundStyle(.white)
            .padding(14)
        }
        .frame(maxWidth: .infinity)
        .frame(height: RX.Metrics.perkTileHeight)
        .clipShape(shape)
        .contentShape(shape)
        .accessibilityElement(children: .combine)
    }
}

// MARK: Glass

extension View {
    /// Native Liquid Glass (iOS, macOS and watchOS 26) in `shape`: interactive for a control, the
    /// dark variant on a photo so white text keeps its contrast. visionOS keeps its own material.
    @ViewBuilder public func rxGlass<S: Shape>(in shape: S, onPhoto: Bool = false, interactive: Bool = true) -> some View {
        #if os(visionOS)
        background(.regularMaterial, in: shape)
        #else
        let glass: Glass = onPhoto ? .regular.tint(.black.opacity(0.18)) : .regular
        glassEffect(interactive ? glass.interactive() : glass, in: shape)
        #endif
    }
}

// MARK: Hero page

/// A page with a photo hero and the rounded page sheet that starts under it (Home and Settings).
/// The photo stays fixed behind the page, under the status bar; only the sheet scrolls up over it.
/// As the sheet rises, the hero (score, pill, actions) fades and shrinks with the scroll offset.
public struct RXHeroPage<Hero: View, Sheet: View>: View {
    let photo: Image
    let hero: Hero
    let sheet: Sheet
    @State private var heroHeight: CGFloat = 320
    /// 0 at rest, 1 once the sheet has covered most of the hero.
    @State private var progress: CGFloat = 0
    @State private var position = ScrollPosition(edge: .top)
    /// Captures only: where the page starts scrolled to (points from the top).
    let initialOffset: CGFloat?
    /// A light photo (dark words over it): a soft white veil instead of the dark scrim.
    let lightPhoto: Bool

    public init(
        photo: Image, lightPhoto: Bool = false, initialOffset: CGFloat? = nil,
        @ViewBuilder hero: () -> Hero, @ViewBuilder sheet: () -> Sheet
    ) {
        self.photo = photo
        self.lightPhoto = lightPhoto
        self.initialOffset = initialOffset
        self.hero = hero()
        self.sheet = sheet()
    }

    /// How far the hero has faded for a scroll offset (`offset` from the resting position).
    public static func fade(offset: CGFloat, heroHeight: CGFloat) -> CGFloat {
        min(max(offset / max(heroHeight * 0.7, 1), 0), 1)
    }

    public var body: some View {
        GeometryReader { proxy in
            ScrollView {
                VStack(spacing: 0) {
                    hero
                        .padding(.top, proxy.safeAreaInsets.top + RX.Space.xs)
                        .padding(.horizontal, RX.Space.gutter)
                        .padding(.bottom, RX.Space.xl)
                        .frame(maxWidth: .infinity)
                        .onGeometryChange(for: CGFloat.self) { $0.size.height } action: { heroHeight = $0 }
                        .opacity(1 - progress)
                        .scaleEffect(1 - 0.1 * progress, anchor: .bottom)
                        .allowsHitTesting(progress < 0.5)
                    sheet
                        .padding(.top, RX.Space.xl)
                        .padding(.horizontal, RX.Space.gutter)
                        .padding(.bottom, RX.Space.xl)
                        .frame(maxWidth: .infinity, minHeight: proxy.size.height * 0.6, alignment: .top)
                        .background(
                            RX.Palette.pageBackground.color,
                            in: UnevenRoundedRectangle(
                                topLeadingRadius: RX.Radius.pageSheet, topTrailingRadius: RX.Radius.pageSheet,
                                style: .continuous))
                }
            }
            .scrollPosition($position)
            .onScrollGeometryChange(for: CGFloat.self) { geometry in
                geometry.contentOffset.y + geometry.contentInsets.top
            } action: { _, offset in
                progress = Self.fade(offset: offset, heroHeight: heroHeight)
            }
            .task {
                guard let initialOffset else { return }
                try? await Task.sleep(for: .milliseconds(600))
                position.scrollTo(y: initialOffset)
            }
            .ignoresSafeArea(edges: .top)
            .background(alignment: .top) {
                // Fixed: the photo never moves with the page.
                ZStack {
                    photo
                        .resizable()
                        .scaledToFill()
                    let veil: Color = lightPhoto ? .white : .black
                    LinearGradient(
                        stops: [
                            .init(color: veil.opacity(lightPhoto ? 0.15 : 0.25), location: 0),
                            .init(color: veil.opacity(lightPhoto ? 0.1 : 0.05), location: 0.55),
                            .init(color: veil.opacity(lightPhoto ? 0.35 : 0.55), location: 1),
                        ],
                        startPoint: .top, endPoint: .bottom)
                }
                .frame(width: proxy.size.width, height: heroHeight + 60)
                .clipped()
                .ignoresSafeArea(edges: .top)
                .accessibilityHidden(true)
            }
            .background(RX.Palette.pageBackground.color.ignoresSafeArea())
        }
    }
}

#Preview("RX blocks") {
    ScrollView {
        VStack(spacing: 16) {
            HStack {
                GlassButton(Text(verbatim: "Close"), systemImage: "xmark") {}
                ColorDisc(systemImage: "creditcard.fill", color: Theme.RX.Hue.blue)
            }
            RXCard {
                RXCardHeader(Text(verbatim: "Recent"), actionTitle: Text(verbatim: "See all")) {}
                RXItemRow(title: Text(verbatim: "Forge Atlas"), subtitle: Text(verbatim: "camille.durand@exemple.fr"),
                          value: Text(verbatim: "2 min"), valueColor: Theme.RX.Palette.textSecondary.color) {
                    ColorDisc(systemImage: "person.fill", color: Theme.RX.Hue.indigo)
                }
            }
            RXCard {
                RXMenuRow(Text(verbatim: "Security"), systemImage: "lock.fill", value: Text(verbatim: "Face ID"))
                RXMenuRow(Text(verbatim: "Sign out"), systemImage: "rectangle.portrait.and.arrow.right",
                          tint: Theme.RX.Palette.negative.color, chevron: false)
            }
            PlanCard(title: Text(verbatim: "Plus"), subtitle: Text(verbatim: "View plan benefits"), art: nil,
                     perks: ["key.fill", "person.3.fill", "airplane", "chevron.right"])
                .background(Color.indigo)
        }
        .padding(16)
    }
    .background(Theme.RX.Palette.pageBackground.color)
}

// MARK: Penpot registry

/// The Penpot main component a SwiftUI view draws, read from source by `dbridge drift`
/// (Soma_Tools/design-bridge), which reports Penpot components with no view, views whose path is
/// gone, and props one side has and the other does not. Keys are Swift parameters; values name
/// the Penpot layer (or the variant axis) they drive. Same shape as DesignBridgeKit's
/// `PenpotComponent`, kept here until DesignKit depends on that package.
public struct PenpotComponent: Sendable, Equatable {
    public enum Prop: Sendable, Equatable {
        /// A text layer of the main component.
        case text(String)
        /// A nested instance the caller swaps (a glyph, a lead).
        case swap(String)
        /// A layer whose fill the caller picks; `(root)` is the component itself.
        case fill(String)
        /// A variant axis and the values this view covers.
        case variant(String, [String])
    }

    /// Penpot path, `/` separated, spaces trimmed (`Row/Menu`, `Button/Icon`).
    public let path: String
    public let props: [String: Prop]

    public init(path: String, props: [String: Prop] = [:]) {
        self.path = path
        self.props = props
    }
}

/// A view that draws one Penpot main component (or one family of variants). The mapping is plain
/// data, so it is `nonisolated` on the (main actor) views.
public protocol PenpotMapped {
    static var penpot: PenpotComponent { get }
}

extension GlassButton: nonisolated PenpotMapped {
    nonisolated public static let penpot = PenpotComponent(path: "Button/Icon", props: [
        "systemImage": .swap("Icon"),
        "onPhoto": .variant("Style", ["Glass", "Glass on photo"]),
        "diameter": .variant("Size", ["S", "M", "L"]),
    ])
}

extension ColorDisc: nonisolated PenpotMapped {
    nonisolated public static let penpot = PenpotComponent(path: "Disc", props: [
        "systemImage": .swap("Icon"),
        "color": .fill("(root)"),
        "diameter": .variant("Size", ["32", "40", "48"]),
    ])
}

extension RXItemRow: nonisolated PenpotMapped {
    nonisolated public static var penpot: PenpotComponent {
        PenpotComponent(path: "Row/Item", props: [
            "title": .text("Title"),
            "subtitle": .text("Subtitle"),
            "value": .text("Value"),
            "valueColor": .fill("Value"),
            "lead": .swap("Site tile"),
        ])
    }
}

extension RXMenuRow: nonisolated PenpotMapped {
    nonisolated public static let penpot = PenpotComponent(path: "Row/Menu", props: [
        "title": .text("Title"),
        "value": .text("Value"),
        "systemImage": .swap("Icon"),
        "badge": .swap("Badge"),
        "tint": .fill("Title"),
    ])
}

extension RXCard: nonisolated PenpotMapped {
    nonisolated public static var penpot: PenpotComponent {
        PenpotComponent(path: "Card/Group", props: ["content": .swap("Row")])
    }
}

extension RXCardHeader: nonisolated PenpotMapped {
    nonisolated public static let penpot = PenpotComponent(path: "Card/Header", props: [
        "title": .text("Title"),
        "actionTitle": .text("Action"),
    ])
}

extension RXStatTile: nonisolated PenpotMapped {
    nonisolated public static let penpot = PenpotComponent(path: "Stat", props: [
        "value": .text("Count"),
        "label": .text("Label"),
        "systemImage": .swap("Disc"),
    ])
}

extension QuickActionLabel: nonisolated PenpotMapped {
    nonisolated public static let penpot = PenpotComponent(path: "Action", props: [
        "title": .text("Title"),
        "systemImage": .swap("Disc"),
    ])
}

extension QuickActionRow: nonisolated PenpotMapped {
    nonisolated public static var penpot: PenpotComponent {
        PenpotComponent(path: "Actions", props: ["content": .swap("Action")])
    }
}

extension PlanCard: nonisolated PenpotMapped {
    nonisolated public static let penpot = PenpotComponent(path: "Card/Plan", props: [
        "title": .text("Plan"),
        "subtitle": .text("Subtitle"),
        "perks": .swap("Perk"),
    ])
}

extension PerkTile: nonisolated PenpotMapped {
    nonisolated public static let penpot = PenpotComponent(path: "Tile", props: [
        "title": .text("Title"),
        "subtitle": .text("Subtitle"),
        "systemImage": .swap("Icon"),
        "kind": .variant("Kind", ["Family vaults", "Travel mode", "Hardware keys"]),
    ])
}
