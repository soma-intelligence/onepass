#if os(macOS)
import DesignBridgeKit
import DesignKit
import SwiftUI
import VaultKit

/// What the Réglages page of the main window shows on its right (RX look, Mac).
enum RXMacSettingsSelection: Hashable {
    /// Profil: the account's name and photo.
    case profile
    case page(SettingsPage)
}

extension EnvironmentValues {
    /// Set by the Réglages page of the main window: shows another category in place (the plan
    /// page's rows, the perk tiles). Nil elsewhere, where those push by value.
    @Entry var rxMacSettingsSelect: ((RXMacSettingsSelection) -> Void)? = nil
    /// True inside the Réglages popup of the main window: the settings forms draw as RX cards.
    @Entry var rxMacSettingsPage = false
    /// The settings forms on screen in the popup's current stack: a form that appears over
    /// another one was pushed, and shows a back button.
    @Entry var rxMacSettingsDepth: RXMacSettingsDepth? = nil
}

/// Counts the settings forms on screen per navigation stack of the Réglages popup (each category
/// gets a fresh stack, `generation`).
struct RXMacSettingsDepth {
    final class Counts { var byGeneration: [Int: Int] = [:] }
    let counts: Counts
    let generation: Int

    var current: Int { counts.byGeneration[generation] ?? 0 }
    func appeared() { counts.byGeneration[generation] = current + 1 }
    func disappeared() { counts.byGeneration[generation] = max(current - 1, 0) }
}

/// Hosts Réglages of the RX look on the Mac as a popup inside the main window: while
/// `AppModel.showSettings` is on, the window dims and blurs under a centred panel. The window's
/// toolbar hides meanwhile, so nothing stays bright above the dimmed backdrop.
struct RXMacSettingsPopupHost: ViewModifier {
    @Environment(AppModel.self) private var model
    @AppStorage(RXDesign.storageKey, store: AppModel.browseDefaults) private var rxDesign = RXDesign.launchDefault
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func body(content: Content) -> some View {
        let shown = rxDesign && model.showSettings && model.session.state == .unlocked
        content
            .toolbar(shown ? .hidden : .automatic, for: .windowToolbar)
            .overlay {
                if shown {
                    RXMacSettingsPopup { model.showSettings = false }
                        .transition(reduceMotion ? .opacity : .opacity.combined(with: .scale(scale: 0.97)))
                }
            }
            .animation(reduceMotion ? .easeOut(duration: 0.15) : .snappy(duration: 0.25), value: shown)
    }
}

/// Réglages on the Mac in the RX look: a popup inside the main window (never a separate window).
/// The window dims and blurs; in the middle, one rounded RX panel, 860 x 620 at most and smaller
/// with the window. On its left the categories (Profil, then the pages in three groups,
/// Verrouiller at the bottom), the selected one on a soft accent pill; on its right the selected
/// page under its title, its sections drawn as RX cards (`RXMacFormStyle`). It opens on Général.
/// The close button, Escape or a click on the backdrop close it. A page's own pushes ("Coffres
/// visibles") stay inside the panel, with a back chevron beside the title.
struct RXMacSettingsPopup: View {
    let close: () -> Void
    @Environment(AppModel.self) private var model
    @State private var selection: RXMacSettingsSelection = RXMacSettingsPopup.initialSelection
    /// A fresh navigation stack per category.
    @State private var stackID = 0
    @State private var depthCounts = RXMacSettingsDepth.Counts()

    private typealias RX = Theme.RX

    /// The widest the cards get inside the panel.
    static let readableWidth: CGFloat = 600
    /// The categories column.
    static let columnWidth: CGFloat = 220
    static let panelSize = CGSize(width: 860, height: 620)

    private static var initialSelection: RXMacSettingsSelection {
        #if DEBUG
        if let name = UserDefaults.standard.string(forKey: "OnePassDemoSettingsPage"), let page = SettingsPage(rawValue: name) {
            return .page(page)
        }
        #endif
        return .page(.general)
    }

    var body: some View {
        GeometryReader { proxy in
            let width = min(Self.panelSize.width, proxy.size.width - 2 * RX.Space.xl)
            let height = min(Self.panelSize.height, proxy.size.height - 2 * RX.Space.xl)
            ZStack {
                backdrop
                panel
                    .frame(width: max(width, 0), height: max(height, 0))
            }
            .frame(width: proxy.size.width, height: proxy.size.height)
        }
        .ignoresSafeArea()
        .onAppear(perform: takeRequest)
        .onChange(of: model.settingsPageRequest) { takeRequest() }
        // Opening another category counts as activity, as a push in Réglages does.
        .onChange(of: selection) {
            model.session.noteActivity()
            stackID &+= 1
        }
        .accessibilityIdentifier("rx.settings")
    }

    /// The window under the panel, blurred and dimmed; a click on it closes.
    private var backdrop: some View {
        ZStack {
            Rectangle().fill(.ultraThinMaterial)
            Color.black.opacity(0.25)
        }
        .contentShape(Rectangle())
        // swiftlint:disable:next db_on_tap_gesture - the dismiss scrim of the popup, not an action
        .onTapGesture(perform: close)
        .accessibilityHidden(true)
    }

    private var panel: some View {
        let shape = RoundedRectangle(cornerRadius: RX.Radius.card, style: .continuous)
        return HStack(spacing: 0) {
            RXMacSettingsColumn(selection: $selection)
                .frame(width: Self.columnWidth)
                .background(RX.Palette.cardBackground.color)
            Rectangle()
                .fill(RX.Palette.separator.color)
                .frame(width: 1)
                .accessibilityHidden(true)
            detail
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .background(RX.Palette.pageBackground.color)
        .clipShape(shape)
        .overlay(shape.strokeBorder(RX.Palette.separator.color, lineWidth: 1))
        .shadow(color: .black.opacity(0.35), radius: 30, y: 12)
        .environment(\.rxCards, true)
        .environment(\.rxMacSettingsSelect) { selection = $0 }
        .overlay(alignment: .topTrailing) {
            Button(action: close) {
                Image(systemName: "xmark")
                    .font(RX.Glyph.font(RX.Glyph.macSmall, weight: .bold))
                    .foregroundStyle(RX.Palette.textSecondary.color)
                    .frame(width: 28, height: 28)
                    .background(RX.Palette.field.color, in: Circle())
                    .contentShape(Circle())
            }
            .buttonStyle(.plain)
            .keyboardShortcut(.cancelAction)
            .help(Text("Fermer"))
            .accessibilityLabel(Text("Fermer"))
            .accessibilityIdentifier("rx.settings.close")
            .padding(RX.Space.m)
        }
    }

    private var detail: some View {
        NavigationStack {
            Group {
                switch selection {
                case .profile:
                    ProfileSettings()
                case .page(let page):
                    page.content
                }
            }
            .safeAreaInset(edge: .top, spacing: 0) { header }
            .navigationDestination(for: SettingsRoute.self) { route in
                switch route {
                case .page(let page): page.content
                case .plan: RXPlanPage()
                }
            }
        }
        // On the stack, so its pushed pages draw as RX cards too (each shows its back button).
        .environment(\.rxMacSettingsPage, true)
        .environment(\.rxMacSettingsDepth, RXMacSettingsDepth(counts: depthCounts, generation: stackID))
        .id(stackID)
        .toolbar(.hidden, for: .windowToolbar)
    }

    /// The category's title over its cards, on the readable width.
    private var header: some View {
        Group {
            switch selection {
            case .profile: Text("Profil")
            case .page(let page): Text(page.title)
            }
        }
        .rxFont(.title)
        .foregroundStyle(RX.Palette.textPrimary.color)
        .dbText(maxLines: 1)
        .accessibilityAddTraits(.isHeader)
        .frame(maxWidth: Self.readableWidth, alignment: .leading)
        .padding(.horizontal, RX.Space.xl)
        .padding(.top, RX.Space.l)
        .padding(.bottom, RX.Space.xs)
        .frame(maxWidth: .infinity)
        .background(RX.Palette.pageBackground.color)
    }

    /// A page asked by another screen (Profil, Développeur, the browser pairing).
    private func takeRequest() {
        guard let request = model.settingsPageRequest else { return }
        selection = .page(request)
        model.settingsPageRequest = nil
    }
}

/// The back button of a page pushed inside the Réglages popup, above its cards on the
/// readable width.
struct RXMacSettingsBackBar: View {
    let back: () -> Void

    private typealias RX = Theme.RX

    var body: some View {
        Button(action: back) {
            Label("common.back", systemImage: "chevron.left")
        }
        .accessibilityIdentifier("rx.settings.back")
        .buttonStyle(RXMacPillButtonStyle())
        .frame(maxWidth: RXMacSettingsPopup.readableWidth, alignment: .leading)
        .padding(.horizontal, RX.Space.xl)
        .padding(.top, RX.Space.l)
        .padding(.bottom, RX.Space.xs)
        .frame(maxWidth: .infinity)
        .background(RX.Palette.pageBackground.color)
    }
}

/// The left pane of Réglages: Profil (the account's photo and name), the categories, then
/// Verrouiller. Rows as the RX sidebar's: a 20 pt glyph, Callout, 34 pt high, the selected one in
/// the accent on a soft pill.
private struct RXMacSettingsColumn: View {
    @Environment(AppModel.self) private var model
    @Binding var selection: RXMacSettingsSelection

    private typealias RX = Theme.RX

    var body: some View {
        let _ = model.settingsRevision
        let name = model.settings.displayName.isEmpty ? String(localized: "Profil") : model.settings.displayName
        ScrollView {
            VStack(alignment: .leading, spacing: RX.Space.xxs) {
                // Profil: one plain row, the avatar in place of the glyph.
                row(Text(verbatim: name), selected: selection == .profile, id: "settings.account") {
                    selection = .profile
                } glyph: {
                    RXAvatar(initials: model.initials, photo: model.profileImage, size: RX.Metrics.macRowGlyph, ring: false)
                }
                group([.general, .security, .autofill, .sync, .devices])
                group([.accounts, .vaults, .contacts, .family, .organisation, .travel, .crypto, .developer])
                #if DEBUG
                group([.about, .iconCheck])
                #else
                group([.about])
                #endif
                // The account menu's words; through `perform`, which asks first when an edit is
                // not saved.
                row(Text("Verrouiller"), selected: false, id: "rx.settings.lock") {
                    model.perform(.lock)
                } glyph: {
                    symbol("lock.fill")
                }
                .padding(.top, RX.Space.m)
            }
            .padding(.horizontal, RX.Space.m)
            .padding(.vertical, RX.Space.l)
        }
        .scrollIndicators(.never)
        .accessibilityIdentifier("rx.settings.categories")
    }

    @ViewBuilder private func group(_ pages: [SettingsPage]) -> some View {
        Rectangle()
            .fill(RX.Palette.separator.color)
            .frame(height: 1)
            .padding(.horizontal, RX.Space.s)
            .padding(.vertical, RX.Space.s)
            .accessibilityHidden(true)
        ForEach(pages) { page in
            row(Text(page.title), selected: selection == .page(page), id: "settings.\(page.rawValue)") {
                selection = .page(page)
            } glyph: {
                symbol(page.symbol)
            }
        }
    }

    private func symbol(_ name: String) -> some View {
        Image(systemName: name)
            .font(RX.Glyph.font(RX.Glyph.macRow, weight: .semibold))
    }

    private func row<Glyph: View>(
        _ title: Text, selected: Bool, id: String, action: @escaping () -> Void, @ViewBuilder glyph: () -> Glyph
    ) -> some View {
        Button(action: action) {
            HStack(spacing: RX.Space.m) {
                glyph()
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

/// The `Settings` window while the RX look is on: Réglages live in the main window, so the window
/// (opened by the app menu's Réglages… or ⌘,) hands over to that page and closes at once.
struct RXSettingsWindowRedirect: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Color.clear
            .frame(width: 1, height: 1)
            .background(WindowCloser())
            .onAppear { model.openSettingsInWindow(bringWindow: true) }
    }

    private struct WindowCloser: NSViewRepresentable {
        func makeNSView(context: Context) -> NSView {
            let view = NSView()
            DispatchQueue.main.async { view.window?.close() }
            return view
        }

        func updateNSView(_ nsView: NSView, context: Context) {
            DispatchQueue.main.async { nsView.window?.close() }
        }
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
            .frame(maxWidth: RXMacSettingsPopup.readableWidth, alignment: .leading)
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
struct RXMacPillButtonStyle: ButtonStyle {
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
