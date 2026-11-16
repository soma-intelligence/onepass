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
            .background {
                Circle()
                    .fill(onPhoto ? AnyShapeStyle(.ultraThinMaterial.opacity(0.6)) : AnyShapeStyle(.ultraThinMaterial))
                    .overlay(Circle().fill(onPhoto ? Color.white.opacity(0.18) : RX.Palette.glass.color))
            }
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
        .background {
            shape.fill(.ultraThinMaterial.opacity(0.7))
                .overlay(shape.fill(Color.white.opacity(0.14)))
                .environment(\.colorScheme, .dark)
        }
        .overlay(shape.strokeBorder(Color.white.opacity(0.12), lineWidth: 1))
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

// MARK: Hero page

/// A page with a photo hero and the rounded page sheet that starts under it (Home and Settings):
/// the photo runs under the status bar and 60 pt under the sheet, with the scrim of the mock.
public struct RXHeroPage<Hero: View, Sheet: View>: View {
    let photo: Image
    let hero: Hero
    let sheet: Sheet

    public init(photo: Image, @ViewBuilder hero: () -> Hero, @ViewBuilder sheet: () -> Sheet) {
        self.photo = photo
        self.hero = hero()
        self.sheet = sheet()
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
                        .background(alignment: .top) {
                            GeometryReader { hero in
                                ZStack {
                                    photo
                                        .resizable()
                                        .scaledToFill()
                                    LinearGradient(
                                        stops: [
                                            .init(color: .black.opacity(0.25), location: 0),
                                            .init(color: .black.opacity(0.05), location: 0.55),
                                            .init(color: .black.opacity(0.55), location: 1),
                                        ],
                                        startPoint: .top, endPoint: .bottom)
                                }
                                .frame(width: hero.size.width, height: hero.size.height + 60)
                                .clipped()
                            }
                            .accessibilityHidden(true)
                        }
                    sheet
                        .padding(.top, RX.Space.xl)
                        .padding(.horizontal, RX.Space.gutter)
                        .padding(.bottom, proxy.safeAreaInsets.bottom + RX.Space.xl)
                        .frame(maxWidth: .infinity)
                        .background(
                            RX.Palette.pageBackground.color,
                            in: UnevenRoundedRectangle(
                                topLeadingRadius: RX.Radius.pageSheet, topTrailingRadius: RX.Radius.pageSheet,
                                style: .continuous))
                }
            }
            .ignoresSafeArea(edges: [.top, .bottom])
            .background(RX.Palette.pageBackground.color.ignoresSafeArea())
        }
    }
}

// MARK: Tab bar

/// One tab of `RXTabBar`.
public struct RXTab<ID: Hashable>: Identifiable {
    public let id: ID
    let title: Text
    let systemImage: String
    let accessibilityIdentifier: String

    public init(id: ID, title: Text, systemImage: String, accessibilityIdentifier: String) {
        self.id = id
        self.title = title
        self.systemImage = systemImage
        self.accessibilityIdentifier = accessibilityIdentifier
    }
}

/// The floating tab bar of the mock: a pill of tabs (glyph over a Caption label, the selected one on
/// a soft fill in the accent) and a separate round search button, both on the tab bar glass.
/// Each tab is a button with the selected trait; the labels scale with Dynamic Type.
public struct RXTabBar<ID: Hashable>: View {
    let tabs: [RXTab<ID>]
    @Binding var selection: ID
    let searchLabel: Text
    let onSearch: () -> Void

    public init(tabs: [RXTab<ID>], selection: Binding<ID>, searchLabel: Text, onSearch: @escaping () -> Void) {
        self.tabs = tabs
        _selection = selection
        self.searchLabel = searchLabel
        self.onSearch = onSearch
    }

    public var body: some View {
        HStack(spacing: RX.Space.l) {
            HStack(spacing: 0) {
                ForEach(tabs) { tab in
                    let selected = tab.id == selection
                    Button {
                        selection = tab.id
                    } label: {
                        VStack(spacing: 3) {
                            Image(systemName: tab.systemImage)
                                .font(.system(size: 20, weight: .semibold))
                                .symbolVariant(selected ? .fill : .none)
                                .frame(height: 24)
                            tab.title
                                .rxFont(.caption)
                                .lineLimit(1)
                                .minimumScaleFactor(0.7)
                        }
                        .foregroundStyle(selected ? RX.Palette.accentText.color : RX.Palette.textPrimary.color)
                        .frame(maxWidth: .infinity, minHeight: 52)
                        .background {
                            if selected { Capsule().fill(RX.Palette.tabActive.color) }
                        }
                        .contentShape(Capsule())
                    }
                    .buttonStyle(.plain)
                    .accessibilityAddTraits(selected ? [.isSelected, .isButton] : .isButton)
                    .accessibilityIdentifier(tab.accessibilityIdentifier)
                }
            }
            .padding(6)
            .background(glass(Capsule()))
            Button(action: onSearch) {
                Image(systemName: "magnifyingglass")
                    .font(.system(size: 22, weight: .semibold))
                    .foregroundStyle(RX.Palette.textPrimary.color)
                    .frame(width: RX.Metrics.tabBarHeight, height: RX.Metrics.tabBarHeight)
                    .background(glass(Circle()))
                    .contentShape(Circle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel(searchLabel)
            .accessibilityIdentifier("rx.tab.search")
        }
        .padding(.horizontal, RX.Space.gutter)
        .accessibilityElement(children: .contain)
    }

    private func glass<S: Shape>(_ shape: S) -> some View {
        shape.fill(.ultraThinMaterial)
            .overlay(shape.fill(RX.Palette.tabBar.color))
            .shadow(color: .black.opacity(0.14), radius: 14, y: 8)
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
