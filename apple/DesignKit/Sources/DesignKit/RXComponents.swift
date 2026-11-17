import DesignBridgeKit
import SwiftUI

// The building blocks of the RX look, one per main component of the Penpot file (page
// "OnePass RX · Components"): glass button, colour disc, item row, menu row, card, quick actions,
// plan card and perk tile. They draw only; the screens wrap them in their own Button,
// NavigationLink, ShareLink or Menu, so the actions stay where they are today.

private typealias RX = Theme.RX

/// The press style of RX controls: DesignBridge's 0.97 press (D-MOTION).
private struct RXPressStyle: ViewModifier {
    func body(content: Content) -> some View {
        content.buttonStyle(.dbPress)
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
            .font(RX.Glyph.font(glyph ?? (diameter * 0.45).rounded()))
            .foregroundStyle(onPhoto ? Color.white : RX.Palette.textPrimary.color)
            // Decorative: the button or link around it carries the label.
            .accessibilityHidden(true)
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
        .rxPress(haptic: .selection)
        .accessibilityLabel(label)
    }
}

// MARK: Discs

/// A white glyph on a coloured disc (the item lead, 44 pt, by default): the lead of an item row,
/// a stat tile.
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
            .font(RX.Glyph.font(Theme.RX.Metrics.discGlyph(diameter: diameter) * 0.85))
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
            .font(RX.Glyph.font(RX.Glyph.chevron, weight: .bold))
            .foregroundStyle(RX.Palette.textTertiary.color)
            .accessibilityHidden(true)
    }
}

// MARK: Rows

/// An item row: a 44 pt lead, the title (Body medium) over its subtitle (Callout, secondary), an
/// optional trailing value, an optional chevron. Pitch 64. Text wraps to two lines, then scales;
/// at accessibility sizes the value moves under the title (no clipping, UX-TEXT-01).
public struct RXItemRow<Lead: View>: View {
    let lead: Lead
    let title: Text
    let subtitle: Text?
    let value: AnyView?
    let valueColor: Color?
    let chevron: Bool
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize

    public init(title: Text, subtitle: Text? = nil, value: Text? = nil, valueColor: Color? = nil,
                chevron: Bool = false, @ViewBuilder lead: () -> Lead) {
        self.lead = lead()
        self.title = title
        self.subtitle = subtitle
        self.value = value.map { AnyView($0.dbText(maxLines: 1)) }
        self.valueColor = valueColor
        self.chevron = chevron
    }

    /// A row whose value is a count: rolling digits (D-MOTION).
    public init(title: Text, subtitle: Text? = nil, count: Int, valueColor: Color? = nil,
                chevron: Bool = false, @ViewBuilder lead: () -> Lead) {
        self.lead = lead()
        self.title = title
        self.subtitle = subtitle
        self.value = AnyView(DBNumber(count))
        self.valueColor = valueColor
        self.chevron = chevron
    }

    public var body: some View {
        HStack(spacing: RX.Space.m) {
            lead
                .frame(width: RX.Metrics.itemLead, height: RX.Metrics.itemLead)
            if dynamicTypeSize.isAccessibilitySize {
                VStack(alignment: .leading, spacing: RX.Space.xs) {
                    texts
                    valueView
                }
                Spacer(minLength: 0)
            } else {
                texts
                Spacer(minLength: RX.Space.s)
                valueView
            }
            if chevron { RXChevron() }
        }
        .padding(.vertical, RX.Space.m)
        .padding(.horizontal, RX.Space.l)
        .frame(minHeight: RX.Metrics.itemPitch)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
    }

    private var texts: some View {
        VStack(alignment: .leading, spacing: RX.Space.xxs) {
            title
                .rxFont(.bodyMedium)
                .foregroundStyle(RX.Palette.textPrimary.color)
                .dbText(maxLines: 2)
            if let subtitle {
                // Usernames and addresses: one line cut in the middle (UX-TEXT-02), never broken
                // between two letters; at accessibility sizes the row has room for two.
                subtitle
                    .rxFont(.callout)
                    .foregroundStyle(RX.Palette.textSecondary.color)
                    .truncationMode(.middle)
                    .dbText(maxLines: dynamicTypeSize.isAccessibilitySize ? 2 : 1)
            }
        }
    }

    @ViewBuilder private var valueView: some View {
        if let value {
            value
                .rxFont(.bodyMedium)
                .monospacedDigit()
                .foregroundStyle(valueColor ?? RX.Palette.textPrimary.color)
        }
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
                .font(RX.Glyph.font(RX.Glyph.menu, weight: .medium))
                .foregroundStyle(ink)
                .frame(width: RX.Metrics.menuGlyph, height: RX.Metrics.menuGlyph)
                .accessibilityHidden(true)
            title
                .rxFont(.bodyMedium)
                .foregroundStyle(ink)
                .dbText(maxLines: 2)
            Spacer(minLength: RX.Space.s)
            if let value {
                value
                    .rxFont(.body)
                    .foregroundStyle(RX.Palette.textSecondary.color)
                    .dbText(maxLines: 1)
            }
            if let badge {
                badge
                    .rxFont(.footnoteBold)
                    .foregroundStyle(RX.Palette.onAccent.color)
                    .padding(.horizontal, RX.Space.s)
                    .frame(minHeight: RX.Metrics.badgeHeight)
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
        .padding(.vertical, RX.Space.s)
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
                .dbText(maxLines: 2)
                .accessibilityAddTraits(.isHeader)
            Spacer(minLength: RX.Space.s)
            if let actionTitle, let action {
                Button(action: action) {
                    actionTitle
                        .rxFont(.calloutMedium)
                        .foregroundStyle(RX.Palette.accentText.color)
                }
                .buttonStyle(.dbPress)
            }
        }
        .padding(.horizontal, RX.Space.l)
        .padding(.top, RX.Space.m)
        .padding(.bottom, RX.Space.xs)
    }
}

/// A short line inside a card that has nothing to list yet: what will appear there, in the
/// card's own words (the empty state of an in-card section).
public struct RXCardMessage: View {
    let text: Text

    public init(_ text: Text) {
        self.text = text
    }

    public var body: some View {
        text
            .rxFont(.callout)
            .foregroundStyle(RX.Palette.textSecondary.color)
            .dbText()
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, RX.Space.l)
            .padding(.top, RX.Space.xs)
            .padding(.bottom, RX.Space.m)
    }
}

extension RXCardMessage: nonisolated PenpotMapped {
    nonisolated public static let penpot = PenpotComponent(path: "Card/Message", props: ["text": .text("Message")])
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

/// A small tile of the stat row (Watchtower): a disc, the count (Title, rolling digits), the label
/// (Footnote).
public struct RXStatTile: View {
    let systemImage: String
    let color: Color
    let value: Int
    let label: Text

    public init(value: Int, label: Text, systemImage: String, color: Color) {
        self.value = value
        self.label = label
        self.systemImage = systemImage
        self.color = color
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: RX.Space.s) {
            ColorDisc(systemImage: systemImage, color: color, diameter: RX.Metrics.statDisc)
            RXNumber(value, typography: .title)
                .foregroundStyle(RX.Palette.textPrimary.color)
            label
                .rxFont(.footnote)
                .foregroundStyle(RX.Palette.textSecondary.color)
                .dbText(maxLines: 3)
        }
        .padding(RX.Space.m)
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
                RXGlassGlyph(systemImage: systemImage, diameter: RX.Metrics.actionDisc, glyph: RX.Glyph.action, onPhoto: true)
            } else {
                Image(systemName: systemImage)
                    .font(RX.Glyph.font(RX.Glyph.action))
                    .foregroundStyle(RX.Palette.accentText.color)
                    .frame(width: RX.Metrics.actionDisc, height: RX.Metrics.actionDisc)
                    .background(RX.Palette.raisedBackground.color, in: Circle())
                    .rxRaisedShadow()
            }
            title
                .rxFont(.calloutMedium)
                .foregroundStyle(onPhoto ? Color.white : RX.Palette.textPrimary.color)
                .multilineTextAlignment(.center)
                .dbText(maxLines: 2, minimumScale: 0.8)
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

/// The Plus card over a photo hero: one translucent dark glass panel (the page sheet radius), the
/// plan name (Title, bold) and one line, a row of 44 pt discs (the last one a chevron), and the art
/// large in the top trailing corner, bleeding off the card's top and trailing edges. The discs are
/// plain white veils, not glass: the panel is already glass (glass only on controls). The card has a
/// smallest height and grows with the text; at accessibility sizes the art goes, so it never
/// covers the words, and the discs stay under the text.
public struct PlanCard: View {
    let title: Text
    let subtitle: Text
    let art: Image?
    let perks: [String]
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    /// `perks`: the SF Symbols of the discs, left to right.
    public init(title: Text, subtitle: Text, art: Image?, perks: [String]) {
        self.title = title
        self.subtitle = subtitle
        self.art = art
        self.perks = perks
    }

    public var body: some View {
        let shape = RoundedRectangle(cornerRadius: RX.Radius.pageSheet, style: .continuous)
        let large = dynamicTypeSize.isAccessibilitySize
        VStack(alignment: .leading, spacing: 0) {
            title
                .rxFont(.title)
                .fontWeight(.bold)
                .foregroundStyle(.white)
                .dbText(maxLines: 2)
            subtitle
                .rxFont(.callout)
                .foregroundStyle(.white)
                .rxOnPhotoSecondary()
                .dbText(maxLines: large ? 4 : 2)
                .padding(.top, RX.Space.xxs)
            Spacer(minLength: RX.Space.m)
            HStack(spacing: RX.Space.s) {
                ForEach(perks, id: \.self) { symbol in
                    RXVeilDisc(systemImage: symbol, diameter: RX.Metrics.glassButton)
                }
            }
            .accessibilityHidden(true)
        }
        // Room on the trailing side for the art, when it is drawn: the tilted art covers about
        // half its width inside the card, so the words stop before it.
        .padding(.trailing, large || art == nil ? 0 : RX.Metrics.planCardArtWidth * 0.5)
        .padding(RX.Metrics.planCardPadding)
        .frame(maxWidth: .infinity, minHeight: RX.Metrics.planCardHeight, alignment: .leading)
        .background(alignment: .topTrailing) {
            if let art, !large {
                // Large and off the corner: the card's shape crops its top and trailing parts.
                art
                    .resizable()
                    .scaledToFit()
                    .frame(width: RX.Metrics.planCardArtWidth)
                    .rotationEffect(.degrees(-8))
                    .offset(x: RX.Metrics.planCardArtWidth * 0.24, y: -RX.Metrics.planCardHeight * 0.24)
                    .accessibilityHidden(true)
            }
        }
        .modifier(PlanCardPanel(
            shape: shape,
            flat: Theme.Wash.isFlat(increaseContrast: contrast == .increased, reduceTransparency: reduceTransparency)))
        .environment(\.colorScheme, .dark)
        .clipShape(shape)
        .contentShape(shape)
        .accessibilityElement(children: .combine)
    }
}

/// The plan card's panel: dark glass, or a plain dark fill under Reduce Transparency or Increase
/// Contrast, so the white words keep their contrast.
private struct PlanCardPanel<S: Shape>: ViewModifier {
    let shape: S
    let flat: Bool

    func body(content: Content) -> some View {
        if flat {
            // A hairline edge too: on a black page (dark mode) the flat panel has no visible edge.
            content
                .background(Color.black.opacity(RX.Veil.hero(flat: true)[2]), in: shape)
                .overlay(shape.stroke(Color.white.opacity(0.22), lineWidth: 2)) // half of it survives the clip
        } else {
            content.rxGlass(in: shape, onPhoto: true, interactive: false)
        }
    }
}

/// A white glyph on a white veil disc: the perks of the plan card and the glyph of a perk tile, on
/// photos or glass, where a second glass layer would be glass on glass.
struct RXVeilDisc: View {
    let systemImage: String
    let diameter: CGFloat

    var body: some View {
        Image(systemName: systemImage)
            .font(RX.Glyph.font((diameter * 0.45).rounded()))
            .foregroundStyle(.white)
            .frame(width: diameter, height: diameter)
            .background(.white.opacity(0.18), in: Circle())
            .accessibilityHidden(true)
    }
}

/// A perk tile of "Get more from Plus": the art full bleed (the perk radius), a dark gradient over
/// its lower half, a small white disc with the glyph, the title (Headline, semibold) and one line
/// (Footnote), all white. It has a smallest height and grows with the text, so the glyph and title
/// are never cut. Reduce Transparency or Increase Contrast darken the gradient.
public struct PerkTile: View {
    let art: Image
    let title: Text
    let subtitle: Text
    let systemImage: String
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    public init(title: Text, subtitle: Text, systemImage: String, art: Image) {
        self.title = title
        self.subtitle = subtitle
        self.systemImage = systemImage
        self.art = art
    }

    public var body: some View {
        let shape = RoundedRectangle(cornerRadius: RX.Radius.perk, style: .continuous)
        let veil = RX.Veil.perk(flat: Theme.Wash.isFlat(
            increaseContrast: contrast == .increased, reduceTransparency: reduceTransparency))
        let lines = dynamicTypeSize.isAccessibilitySize ? 4 : 2
        VStack(alignment: .leading, spacing: RX.Space.xxs) {
            Spacer(minLength: 0)
            RXVeilDisc(systemImage: systemImage, diameter: RX.Metrics.perkGlyph)
                .padding(.bottom, RX.Space.s)
            title
                .rxFont(.headline)
                .fontWeight(.semibold)
                .dbText(maxLines: lines)
            subtitle
                .rxFont(.footnote)
                .rxOnPhotoSecondary()
                .dbText(maxLines: lines)
        }
        .foregroundStyle(.white)
        .padding(RX.Space.m)
        .frame(maxWidth: .infinity, minHeight: RX.Metrics.perkTileHeight, alignment: .bottomLeading)
        .background {
            ZStack {
                RX.Wash.artPlaceholder
                art
                    .resizable()
                    .scaledToFill()
                    .frame(minWidth: 0, maxWidth: .infinity, minHeight: 0, maxHeight: .infinity)
                    .clipped()
                    .accessibilityHidden(true)
                LinearGradient(
                    stops: [
                        .init(color: .black.opacity(0), location: 0),
                        .init(color: .black.opacity(veil.middle), location: 0.5),
                        .init(color: .black.opacity(veil.bottom), location: 1),
                    ],
                    startPoint: .top, endPoint: .bottom)
            }
        }
        .clipShape(shape)
        .contentShape(shape)
        .accessibilityElement(children: .combine)
    }
}

/// Secondary white text on a photo: dimmed, at full opacity under Reduce Transparency or
/// Increase Contrast.
private struct RXOnPhotoSecondary: ViewModifier {
    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    func body(content: Content) -> some View {
        content.opacity(RX.Veil.secondaryText(flat: Theme.Wash.isFlat(
            increaseContrast: contrast == .increased, reduceTransparency: reduceTransparency)))
    }
}

extension View {
    /// Secondary white text on a photo or a dark glass panel (`Theme.RX.Veil.secondaryText`).
    public func rxOnPhotoSecondary() -> some View {
        modifier(RXOnPhotoSecondary())
    }

    /// The one shadow of raised RX controls (`Theme.RX.Shadow`).
    public func rxRaisedShadow() -> some View {
        shadow(color: .black.opacity(RX.Shadow.raisedOpacity), radius: RX.Shadow.raisedRadius, y: RX.Shadow.raisedY)
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

/// A page with a photo hero and the rounded page sheet that starts under it (Home and Settings),
/// on DesignBridge's `DBScrollHero` (D-HOME-HERO): the photo stays fixed behind the page, under
/// the status bar; only the sheet scrolls up over it, and the hero (score, pill, actions) fades
/// and shrinks as the sheet covers it. The hero area sizes to its content, so it grows with
/// Dynamic Type instead of sliding under the sheet.
public struct RXHeroPage<Hero: View, Sheet: View>: View {
    let photo: Image
    let hero: Hero
    let sheet: Sheet
    @State private var position = ScrollPosition(edge: .top)
    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    /// Captures only: where the page starts scrolled to (points from the top).
    let initialOffset: CGFloat?
    /// A light photo (dark words over it): a soft white veil instead of the dark scrim.
    let lightPhoto: Bool
    /// Each change scrolls the page back to its top (a tap on the tab that is already selected).
    let scrollToTop: Int

    public init(
        photo: Image, lightPhoto: Bool = false, initialOffset: CGFloat? = nil, scrollToTop: Int = 0,
        @ViewBuilder hero: () -> Hero, @ViewBuilder sheet: () -> Sheet
    ) {
        self.photo = photo
        self.lightPhoto = lightPhoto
        self.initialOffset = initialOffset
        self.scrollToTop = scrollToTop
        self.hero = hero()
        self.sheet = sheet()
    }

    public var body: some View {
        DBScrollHero(heroHeight: nil, parallax: nil, position: $position) {
            backdrop
        } header: {
            hero
                .padding(.top, RX.Space.xs)
                .frame(maxWidth: .infinity)
        } content: {
            sheet
                .padding(.top, RX.Space.xl)
                .padding(.horizontal, RX.Space.gutter)
                .padding(.bottom, RX.Space.xl)
        }
        .task {
            guard let initialOffset else { return }
            try? await Task.sleep(for: .milliseconds(600))
            position.scrollTo(y: initialOffset)
        }
        .onChange(of: scrollToTop) {
            withDBAnimation(.smooth, reduceMotion: reduceMotion) { position.scrollTo(edge: .top) }
        }
    }

    /// Fixed: the photo never moves with the page. Reduce Transparency or Increase Contrast give a
    /// stronger veil, so the words over it keep their contrast.
    private var backdrop: some View {
        let flat = Theme.Wash.isFlat(increaseContrast: contrast == .increased, reduceTransparency: reduceTransparency)
        let veil: Color = lightPhoto ? .white : .black
        let stops = lightPhoto ? RX.Veil.lightHero(flat: flat) : RX.Veil.hero(flat: flat)
        return ZStack {
            photo
                .resizable()
                .scaledToFill()
                .accessibilityHidden(true)
            LinearGradient(
                stops: [
                    .init(color: veil.opacity(stops[0]), location: 0),
                    .init(color: veil.opacity(stops[1]), location: 0.55),
                    .init(color: veil.opacity(stops[2]), location: 1),
                ],
                startPoint: .top, endPoint: .bottom)
        }
    }
}

extension RXHeroPage: nonisolated PenpotMapped {
    nonisolated public static var penpot: PenpotComponent {
        PenpotComponent(path: "Hero", props: [
            "photo": .swap("Backdrop"),
            "hero": .swap("Header"),
            "sheet": .swap("Sheet"),
        ])
    }
}

// MARK: Carousels

/// A horizontal carousel (D-CAROUSELS): a title, then tiles that snap one by one with the next
/// one peeking at the trailing edge. `bleed` is the page gutter the row runs under, so it scrolls
/// edge to edge while its first tile lines up with the cards.
public struct RXCarousel<Item: Identifiable, Tile: View>: View {
    let title: Text?
    let items: [Item]
    let spacing: CGFloat
    let bleed: CGFloat
    let inset: CGFloat
    let tile: (Item) -> Tile
    @Binding var position: ScrollPosition

    public init(
        _ title: Text?, items: [Item], spacing: CGFloat = Theme.RX.Space.m, bleed: CGFloat = 0,
        inset: CGFloat = 0, position: Binding<ScrollPosition> = .constant(ScrollPosition(idType: String.self)),
        @ViewBuilder tile: @escaping (Item) -> Tile
    ) {
        self.title = title
        self.items = items
        self.spacing = spacing
        self.bleed = bleed
        self.inset = inset
        self.tile = tile
        self._position = position
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: RX.Space.s) {
            if let title {
                title
                    .rxFont(.headline)
                    .foregroundStyle(RX.Palette.textPrimary.color)
                    .dbText(maxLines: 2)
                    .accessibilityAddTraits(.isHeader)
                    .padding(.horizontal, RX.Space.xs)
            }
            ScrollView(.horizontal) {
                LazyHStack(alignment: .top, spacing: spacing) {
                    ForEach(items) { item in
                        tile(item)
                    }
                }
                .scrollTargetLayout()
            }
            .scrollPosition($position)
            .scrollTargetBehavior(.viewAligned)
            .scrollIndicators(.hidden)
            .contentMargins(.horizontal, bleed + inset, for: .scrollContent)
            .padding(.horizontal, -bleed)
        }
    }
}

extension RXCarousel: nonisolated PenpotMapped {
    nonisolated public static var penpot: PenpotComponent {
        PenpotComponent(path: "Carousel", props: [
            "title": .text("Title"),
            "tile": .swap("Tile"),
            "kind": .variant("Kind", ["Favorites", "Perks"]),
        ])
    }
}

/// A favourite of the Home carousel: the item's logo (60 pt, the real brand mark) over its title
/// (Footnote, two lines reserved so the row stays even).
public struct RXFavoriteTile<Logo: View>: View {
    let title: Text
    let logo: Logo
    /// The tile widens with the text size, so a two-word name keeps whole words.
    @ScaledMetric(relativeTo: .footnote) private var width = Theme.RX.Metrics.favoriteWidth
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize

    public init(title: Text, @ViewBuilder logo: () -> Logo) {
        self.title = title
        self.logo = logo()
    }

    public var body: some View {
        VStack(spacing: RX.Space.s) {
            logo
                .frame(width: RX.Metrics.favoriteLogo, height: RX.Metrics.favoriteLogo)
            title
                .rxFont(.footnote)
                .foregroundStyle(RX.Palette.textPrimary.color)
                .multilineTextAlignment(.center)
                .dbText(maxLines: dynamicTypeSize.isAccessibilitySize ? 3 : 2)
                .frame(maxHeight: .infinity, alignment: .top)
        }
        .frame(width: width)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
    }
}

extension RXFavoriteTile: nonisolated PenpotMapped {
    nonisolated public static var penpot: PenpotComponent {
        PenpotComponent(path: "Tile/Favorite", props: [
            "title": .text("Title"),
            "logo": .swap("Logo tile"),
        ])
    }
}

// MARK: Verification code

/// The verification code card (D-CODE-SIZE, D-CODE-LABEL): the label "Code de vérification",
/// then the two groups of digits at 30 pt (tabular, rolling) centred, with the 36 pt timer ring
/// after them. The digits scale with Dynamic Type; at accessibility sizes the ring moves under
/// the digits so nothing is clipped.
public struct RXCodeCard: View {
    let label: Text
    let code: String
    let remaining: Int
    let fraction: Double
    @ScaledMetric(relativeTo: .title) private var digits = Theme.RX.Metrics.codeDigits
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize

    public init(label: Text, code: String, remaining: Int, fraction: Double) {
        self.label = label
        self.code = code
        self.remaining = remaining
        self.fraction = fraction
    }

    /// "538262" gives ["538", "262"]; other lengths of 6 or more are split in halves, a shorter
    /// code stays whole.
    public static func groups(_ code: String) -> [String] {
        guard code.count >= 6 else { return [code] }
        let half = code.index(code.startIndex, offsetBy: code.count / 2)
        return [String(code[..<half]), String(code[half...])]
    }

    public var body: some View {
        VStack(spacing: RX.Space.s) {
            label
                .rxFont(.footnoteBold)
                .foregroundStyle(RX.Palette.accentText.color)
                .dbText(maxLines: 2)
            let layout = dynamicTypeSize.isAccessibilitySize
                ? AnyLayout(VStackLayout(spacing: RX.Space.s)) : AnyLayout(HStackLayout(spacing: RX.Space.m))
            layout {
                HStack(spacing: RX.Space.s) {
                    ForEach(Array(Self.groups(code).enumerated()), id: \.offset) { _, group in
                        Text(verbatim: group)
                            .contentTransition(.numericText())
                    }
                }
                .font(RX.Glyph.codeFont(size: digits))
                .foregroundStyle(RX.Palette.textPrimary.color)
                .lineLimit(1)
                .minimumScaleFactor(0.7)
                .dbAnimation(.snappy, value: code)
                .accessibilityElement(children: .ignore)
                .accessibilityLabel(label)
                .accessibilityValue(Text(verbatim: code))
                RXTimerRing(remaining: remaining, fraction: fraction)
            }
        }
        .frame(maxWidth: .infinity)
    }
}

extension RXCodeCard: nonisolated PenpotMapped {
    nonisolated public static let penpot = PenpotComponent(path: "Card/Verification code", props: [
        "label": .text("Label"),
        "code": .text("Code"),
        "remaining": .text("Seconds"),
    ])
}

/// The countdown of a verification code: 36 pt, a faint track and the accent arc draining, the
/// seconds in the middle (rolling digits); over the last five seconds, red with a heavier arc and
/// heavier digits.
public struct RXTimerRing: View {
    let remaining: Int
    let fraction: Double

    /// The last five seconds.
    public static func isUrgent(_ remaining: Int) -> Bool { remaining <= 5 }

    public init(remaining: Int, fraction: Double) {
        self.remaining = remaining
        self.fraction = fraction
    }

    public var body: some View {
        let urgent = Self.isUrgent(remaining)
        let color = urgent ? RX.Palette.negative.color : RX.Palette.accent.color
        // Not colour alone: the last seconds also draw a heavier arc and heavier digits. The
        // change is a plain swap, never animated, so it is static under Reduce Motion too.
        let stroke = urgent ? RX.Metrics.codeRingUrgentStroke : RX.Metrics.codeRingStroke
        ZStack {
            Circle().stroke(RX.Palette.textTertiary.color.opacity(0.4), lineWidth: RX.Metrics.codeRingStroke)
            Circle()
                .trim(from: 0, to: min(max(fraction, 0), 1))
                .stroke(color, style: StrokeStyle(lineWidth: stroke, lineCap: .round))
                .rotationEffect(.degrees(-90))
            DBNumber(remaining)
                .rxFont(.footnoteBold)
                .fontWeight(urgent ? .black : nil)
                .monospacedDigit()
                .foregroundStyle(urgent ? color : RX.Palette.accentText.color)
        }
        // Half the heavier stroke: the arc stays inside the frame.
        .padding(RX.Metrics.codeRingUrgentStroke / 2)
        .frame(width: RX.Metrics.codeRing, height: RX.Metrics.codeRing)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("rx.code.secondsLeft \(remaining)", bundle: .module))
    }
}

// swiftlint:disable db_unlocalized_string - fixture text of the preview only
#Preview("RX blocks") {
    ScrollView {
        VStack(spacing: Theme.RX.Space.l) {
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
        .padding(Theme.RX.Space.l)
    }
    .background(Theme.RX.Palette.pageBackground.color)
}

// swiftlint:enable db_unlocalized_string

// MARK: Penpot registry

// `PenpotComponent` and `PenpotMapped` live in DesignBridgeKit; `dbridge drift`
// (Soma_Tools/design-bridge) reads these declarations from source.

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
