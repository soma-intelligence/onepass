#if os(macOS)
import DesignBridgeKit
import DesignKit
import SwiftUI
import VaultKit

/// What the Réglages page of the main window shows on its right (RX look, Mac).
enum RXMacSettingsSelection: Hashable {
    /// The account: the photo banner with the Plus strip, then "Get more from Plus".
    case overview
    /// The page of the Plus strip.
    case plan
    case page(SettingsPage)
}

extension EnvironmentValues {
    /// Set by the Réglages page of the main window: shows another category in place (the perk
    /// tiles, the plan page's rows). Nil elsewhere, where those push by value.
    @Entry var rxMacSettingsSelect: ((RXMacSettingsSelection) -> Void)? = nil
    /// True inside the Réglages page of the main window: the settings forms draw as RX cards.
    @Entry var rxMacSettingsPage = false
}

/// Réglages on the Mac in the RX look: a page of the main window, right of the sidebar, like
/// Accueil or Watchtower (no separate `Settings` window while the switch is on). Two panes, as in
/// the system's own settings: on the left a column of categories (the account on top, then the
/// pages in three groups, Verrouiller at the bottom), the selected one on a soft accent pill; on
/// the right the selected page under its title, its sections drawn as RX cards (`RXMacFormStyle`)
/// at a readable width. A page's own pushes ("Coffres visibles") go through the column's
/// navigation stack, with the window's toolbar back button.
struct RXMacSettingsPage: View {
    @Environment(AppModel.self) private var model
    @State private var selection: RXMacSettingsSelection = RXMacSettingsPage.initialSelection
    @State private var showProfileQR = RXMacSettingsPage.demoOpens("profileQR")

    private typealias RX = Theme.RX

    /// The widest the content gets, centred in the pane (Profil's readable width).
    static let readableWidth: CGFloat = 640
    /// The categories column.
    static let columnWidth: CGFloat = 232

    /// Screenshots (Debug): `-OnePassDemoRXSettings plan|profileQR`, as on the iPhone.
    private static func demoOpens(_ name: String) -> Bool {
        #if DEBUG
        UserDefaults.standard.string(forKey: "OnePassDemoRXSettings") == name
        #else
        false
        #endif
    }

    private static var initialSelection: RXMacSettingsSelection {
        #if DEBUG
        if let name = UserDefaults.standard.string(forKey: "OnePassDemoSettingsPage"), let page = SettingsPage(rawValue: name) {
            return .page(page)
        }
        #endif
        return demoOpens("plan") ? .plan : .overview
    }

    var body: some View {
        HStack(spacing: 0) {
            RXMacSettingsColumn(selection: $selection)
                .frame(width: Self.columnWidth)
            Rectangle()
                .fill(RX.Palette.separator.color)
                .frame(width: 1)
                .accessibilityHidden(true)
            detail
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .background(RX.Palette.pageBackground.color)
        .environment(\.rxCards, true)
        .environment(\.rxMacSettingsSelect) { selection = $0 }
        // The pages' value links (a perk tile or a plan row outside this page) still land here.
        .navigationDestination(for: SettingsRoute.self) { route in
            switch route {
            case .page(let page): formPage(page)
            case .plan: RXPlanPage()
            }
        }
        .sheet(isPresented: $showProfileQR) { RXProfileQRSheet() }
        .onAppear(perform: takeRequest)
        .onChange(of: model.settingsPageRequest) { takeRequest() }
        // Opening another category counts as activity, as a push in Réglages does.
        .onChange(of: selection) { model.session.noteActivity() }
        .accessibilityIdentifier("rx.settings")
    }

    @ViewBuilder private var detail: some View {
        switch selection {
        case .overview:
            RXMacSettingsOverview(showProfileQR: $showProfileQR)
        case .plan:
            RXPlanPage()
        case .page(let page):
            formPage(page).id(page)
        }
    }

    /// A page of Réglages under its title, both on the readable width.
    private func formPage(_ page: SettingsPage) -> some View {
        VStack(spacing: 0) {
            Text(page.title)
                .rxFont(.title)
                .foregroundStyle(RX.Palette.textPrimary.color)
                .dbText(maxLines: 2)
                .accessibilityAddTraits(.isHeader)
                .frame(maxWidth: Self.readableWidth, alignment: .leading)
                .padding(.horizontal, RX.Space.xl)
                .padding(.top, RX.Space.l)
                .padding(.bottom, RX.Space.s)
                .frame(maxWidth: .infinity)
            page.content
                .environment(\.rxMacSettingsPage, true)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    /// A page asked by another screen (Profil, Développeur, the browser pairing).
    private func takeRequest() {
        guard let request = model.settingsPageRequest else { return }
        selection = .page(request)
        model.settingsPageRequest = nil
    }
}

/// The left pane of Réglages: the account, then the categories, then Verrouiller. Rows as the RX
/// sidebar's: a 20 pt glyph, Callout, 34 pt high, the selected one in the accent on a soft pill.
private struct RXMacSettingsColumn: View {
    @Environment(AppModel.self) private var model
    @Binding var selection: RXMacSettingsSelection

    private typealias RX = Theme.RX

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: RX.Space.xxs) {
                accountRow
                    .padding(.bottom, RX.Space.s)
                group([.general, .security, .autofill, .sync, .devices])
                group([.accounts, .vaults, .contacts, .family, .organisation, .travel, .crypto, .developer])
                #if DEBUG
                group([.about, .iconCheck])
                #else
                group([.about])
                #endif
                // The account menu's words; through `perform`, which asks first when an edit is
                // not saved.
                row(Text("Verrouiller"), symbol: "lock.fill", selected: false, id: "rx.settings.lock") {
                    model.perform(.lock)
                }
                .padding(.top, RX.Space.m)
            }
            .padding(.horizontal, RX.Space.m)
            .padding(.vertical, RX.Space.l)
        }
        .scrollIndicators(.never)
        .accessibilityIdentifier("rx.settings.categories")
    }

    /// The account: avatar, name and the kind of device; it shows the overview.
    private var accountRow: some View {
        let _ = model.settingsRevision
        let name = model.settings.displayName.isEmpty ? String(localized: "app.myAccount") : model.settings.displayName
        let selected = selection == .overview || selection == .plan
        return Button { selection = .overview } label: {
            HStack(spacing: RX.Space.s) {
                RXAvatar(initials: model.initials, photo: model.profileImage, size: RX.Metrics.avatarSmall, ring: false)
                VStack(alignment: .leading, spacing: 0) {
                    Text(verbatim: name)
                        .rxFont(.calloutMedium)
                        .foregroundStyle(selected ? RX.Palette.accentText.color : RX.Palette.textPrimary.color)
                        .dbText(maxLines: 1)
                    Text(model.settings.deviceMode == .shared
                         ? String(localized: "Appareil partagé") : String(localized: "Appareil personnel"))
                        .rxFont(.footnote)
                        .foregroundStyle(RX.Palette.textSecondary.color)
                        .dbText(maxLines: 1)
                }
                Spacer(minLength: 0)
            }
            .padding(.horizontal, RX.Space.s)
            .padding(.vertical, RX.Space.s)
            .background {
                if selected {
                    RoundedRectangle(cornerRadius: RX.Radius.macRow, style: .continuous)
                        .fill(RX.Palette.accentSoft.color)
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
        .accessibilityIdentifier("settings.account")
    }

    @ViewBuilder private func group(_ pages: [SettingsPage]) -> some View {
        Rectangle()
            .fill(RX.Palette.separator.color)
            .frame(height: 1)
            .padding(.horizontal, RX.Space.s)
            .padding(.vertical, RX.Space.s)
            .accessibilityHidden(true)
        ForEach(pages) { page in
            row(Text(page.title), symbol: page.symbol, selected: selection == .page(page), id: "settings.\(page.rawValue)") {
                selection = .page(page)
            }
        }
    }

    private func row(_ title: Text, symbol: String, selected: Bool, id: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: RX.Space.m) {
                Image(systemName: symbol)
                    .font(RX.Glyph.font(RX.Glyph.macRow, weight: .semibold))
                    .frame(width: RX.Metrics.macRowGlyph, height: RX.Metrics.macRowGlyph)
                    .accessibilityHidden(true)
                title
                    .dbText(maxLines: 1)
                Spacer(minLength: 0)
            }
            .rxFont(selected ? .calloutMedium : .callout)
            .foregroundStyle(selected ? RX.Palette.accentText.color : RX.Palette.textPrimary.color)
            .padding(.horizontal, RX.Space.s)
            .frame(minHeight: RX.Metrics.macRowHeight)
            .background {
                if selected {
                    RoundedRectangle(cornerRadius: RX.Radius.macRow, style: .continuous)
                        .fill(RX.Palette.accentSoft.color)
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(selected ? .isSelected : [])
        .accessibilityIdentifier(id)
    }
}

/// The account side of Réglages: the photo banner (the account, its QR button and the compact
/// Plus strip), then "Get more from Plus" as a grid of four tiles.
private struct RXMacSettingsOverview: View {
    @Environment(AppModel.self) private var model
    @Environment(\.rxMacSettingsSelect) private var select
    @Binding var showProfileQR: Bool
    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    private typealias RX = Theme.RX

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: RX.Space.l) {
                Text("Réglages")
                    .rxFont(.title)
                    .foregroundStyle(RX.Palette.textPrimary.color)
                    .accessibilityAddTraits(.isHeader)
                banner
                Text("rx.perks.title")
                    .rxFont(.headline)
                    .foregroundStyle(RX.Palette.textPrimary.color)
                    .accessibilityAddTraits(.isHeader)
                    .padding(.top, RX.Space.s)
                RXPerkCarousel()
            }
            .frame(maxWidth: RXMacSettingsPage.readableWidth, alignment: .leading)
            .padding(.horizontal, RX.Space.xl)
            .padding(.top, RX.Space.l)
            .padding(.bottom, RX.Space.xl)
            .frame(maxWidth: .infinity)
        }
    }

    /// The photo banner: the account with its QR button, then the Plus strip.
    private var banner: some View {
        let _ = model.settingsRevision
        let name = model.settings.displayName.isEmpty ? String(localized: "app.myAccount") : model.settings.displayName
        return VStack(alignment: .leading, spacing: RX.Space.l) {
            HStack(spacing: RX.Space.m) {
                RXAvatar(initials: model.initials, photo: model.profileImage, size: RX.Metrics.avatarMedium)
                VStack(alignment: .leading, spacing: RX.Space.xxs) {
                    Text(verbatim: name)
                        .rxFont(.headline)
                        .foregroundStyle(.white)
                        .dbText(maxLines: 2)
                    Text(model.settings.deviceMode == .shared
                         ? String(localized: "Appareil partagé") : String(localized: "Appareil personnel"))
                        .rxFont(.footnote)
                        .foregroundStyle(.white)
                        .rxOnPhotoSecondary()
                }
                Spacer(minLength: RX.Space.s)
                GlassButton(Text("rx.profileQR.open"), systemImage: "qrcode", diameter: 36, onPhoto: true) { showProfileQR = true }
                    .accessibilityIdentifier("rx.settings.profileQR")
            }
            Button { select?(.plan) } label: { RXMacPlanStrip() }
                .buttonStyle(.dbPress)
                .accessibilityIdentifier("rx.settings.plan")
        }
        .padding(RX.Space.l)
        .background {
            Image(RXHero.settings)
                .resizable()
                .scaledToFill()
                .overlay(Color.black.opacity(RX.Veil.banner(flat: Theme.Wash.isFlat(
                    increaseContrast: contrast == .increased, reduceTransparency: reduceTransparency))))
                .accessibilityHidden(true)
        }
        .clipShape(RoundedRectangle(cornerRadius: RX.Radius.card, style: .continuous))
    }
}

/// The Plus card on the Mac: one compact glass strip (64 pt) instead of the iPhone's tall card.
/// The metal card art small and tilted on the left, "Plus" over one line, three small perk glyphs
/// and a chevron on the right.
private struct RXMacPlanStrip: View {
    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    private typealias RX = Theme.RX

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: RX.Radius.tile, style: .continuous)
        let flat = Theme.Wash.isFlat(increaseContrast: contrast == .increased, reduceTransparency: reduceTransparency)
        HStack(spacing: RX.Space.m) {
            Image("rx-plan-lux")
                .resizable()
                .scaledToFit()
                .frame(width: 52)
                .rotationEffect(.degrees(-10))
                .shadow(color: .black.opacity(0.4), radius: 6, y: 3)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 0) {
                // swiftlint:disable:next db_unlocalized_string - plan name, the same in every language
                Text(verbatim: "Plus")
                    .rxFont(.headline)
                    .fontWeight(.bold)
                Text("rx.plan.cardSubtitle")
                    .rxFont(.footnote)
                    .rxOnPhotoSecondary()
                    .dbText(maxLines: 1)
            }
            .foregroundStyle(.white)
            Spacer(minLength: RX.Space.s)
            HStack(spacing: RX.Space.xs) {
                ForEach(["key.fill", "person.3.fill", "airplane"], id: \.self) { symbol in
                    Image(systemName: symbol)
                        .font(RX.Glyph.font(11))
                        .foregroundStyle(.white)
                        .frame(width: 26, height: 26)
                        .background(.white.opacity(0.18), in: Circle())
                }
            }
            .accessibilityHidden(true)
            Image(systemName: "chevron.right")
                .font(RX.Glyph.font(RX.Glyph.chevron, weight: .bold))
                .foregroundStyle(.white.opacity(0.7))
                .accessibilityHidden(true)
        }
        .padding(.horizontal, RX.Space.m)
        .frame(height: 64)
        .background {
            if flat {
                shape.fill(Color.black.opacity(0.75))
            } else {
                shape.fill(Color.black.opacity(0.28))
                    .background(.ultraThinMaterial, in: shape)
                    .environment(\.colorScheme, .dark)
            }
        }
        .overlay(shape.strokeBorder(.white.opacity(0.14), lineWidth: 1))
        .clipShape(shape)
        .contentShape(shape)
        .accessibilityElement(children: .combine)
    }
}

// MARK: - The forms of Réglages as RX cards

/// The settings forms inside the Réglages page of the main window (RX look, Mac). Every page keeps
/// its `Form` (settings, sheets and identifiers stay); this style draws it: a scroll view on the
/// page colour, the readable width centred, each section a card (card token, tile radius, 1 pt
/// separators inset by the row padding) with its header above it (Headline) and its footer under
/// it (Footnote, secondary). Rows are Callout, 44 pt at least; switches, values and pickers sit on
/// the trailing edge; buttons are soft field-coloured pills.
struct RXMacFormStyle: FormStyle {
    private typealias RX = Theme.RX

    func makeBody(configuration: Configuration) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: RX.Space.l) {
                Group(sections: configuration.content) { sections in
                    ForEach(sections) { section in
                        RXMacFormSection(section: section)
                    }
                }
            }
            .frame(maxWidth: RXMacSettingsPage.readableWidth, alignment: .leading)
            .padding(.horizontal, RX.Space.xl)
            .padding(.top, RX.Space.s)
            .padding(.bottom, RX.Space.xxl)
            .frame(maxWidth: .infinity)
        }
        // A sheet that uses a settings form sizes to this (a page gets the pane's size).
        .frame(minWidth: 380, idealWidth: 600, minHeight: 260, idealHeight: 560)
        .background(RX.Palette.pageBackground.color)
        .rxFont(.callout)
        .foregroundStyle(RX.Palette.textPrimary.color)
        .tint(RX.Palette.accent.color)
        .toggleStyle(RXMacSwitchStyle())
        .labeledContentStyle(RXMacLabeledContentStyle())
        .buttonStyle(RXMacPillButtonStyle())
        .pickerStyle(.menu)
    }
}

private struct RXMacFormSection: View {
    let section: SectionConfiguration

    private typealias RX = Theme.RX

    var body: some View {
        VStack(alignment: .leading, spacing: RX.Space.s) {
            if !section.header.isEmpty {
                section.header
                    .rxFont(.headline)
                    .foregroundStyle(RX.Palette.textPrimary.color)
                    .textCase(nil)
                    .padding(.horizontal, RX.Space.xs)
                    .accessibilityAddTraits(.isHeader)
            }
            if !section.content.isEmpty {
                let firstID = section.content.first?.id
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(section.content) { row in
                        if row.id != firstID {
                            Rectangle()
                                .fill(RX.Palette.separator.color)
                                .frame(height: 1)
                                .padding(.leading, RX.Space.l)
                                .accessibilityHidden(true)
                        }
                        row
                            .frame(maxWidth: .infinity, minHeight: 28, alignment: .leading)
                            .padding(.horizontal, RX.Space.l)
                            .padding(.vertical, RX.Space.s)
                            .frame(minHeight: 44)
                    }
                }
                .padding(.vertical, RX.Space.xxs)
                .background(RX.Palette.cardBackground.color,
                            in: RoundedRectangle(cornerRadius: RX.Radius.tile, style: .continuous))
            }
            if !section.footer.isEmpty {
                section.footer
                    .rxFont(.footnote)
                    .foregroundStyle(RX.Palette.textSecondary.color)
                    .textCase(nil)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.horizontal, RX.Space.xs)
            }
        }
    }
}

/// A switch on the trailing edge, the label (which may hold a subtitle) taking the rest.
private struct RXMacSwitchStyle: ToggleStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: Theme.RX.Space.m) {
            configuration.label
                .frame(maxWidth: .infinity, alignment: .leading)
            Toggle(isOn: configuration.$isOn) { configuration.label }
                .toggleStyle(.switch)
                .labelsHidden()
                .controlSize(.small)
        }
    }
}

/// A label on the leading edge, its value (secondary) or control on the trailing edge.
private struct RXMacLabeledContentStyle: LabeledContentStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: Theme.RX.Space.m) {
            configuration.label
                .frame(maxWidth: .infinity, alignment: .leading)
            configuration.content
                .foregroundStyle(Theme.RX.Palette.textSecondary.color)
                .multilineTextAlignment(.trailing)
        }
    }
}

/// A button of a settings card: a soft pill in the field token, Callout medium, in the primary
/// text colour (the negative token for a destructive one), a little darker while pressed.
private struct RXMacPillButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled

    private typealias RX = Theme.RX

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .rxFont(.calloutMedium)
            .foregroundStyle(configuration.role == .destructive ? RX.Palette.negative.color : RX.Palette.textPrimary.color)
            .labelStyle(RXMacPillLabelStyle())
            .padding(.horizontal, RX.Space.m)
            .frame(minHeight: 30)
            .background(RX.Palette.field.color.opacity(configuration.isPressed ? 0.6 : 1),
                        in: RoundedRectangle(cornerRadius: RX.Radius.macRow, style: .continuous))
            .contentShape(RoundedRectangle(cornerRadius: RX.Radius.macRow, style: .continuous))
            .opacity(isEnabled ? 1 : 0.45)
    }
}

/// The glyph and title of a pill, 6 pt apart.
private struct RXMacPillLabelStyle: LabelStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 6) {
            configuration.icon
                .font(Theme.RX.Glyph.font(Theme.RX.Glyph.macSmall, weight: .semibold))
                .accessibilityHidden(true)
            configuration.title
        }
    }
}
#endif
