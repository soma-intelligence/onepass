import DesignBridgeKit
import DesignKit
import ImageIO
#if os(iOS)
import PhotosUI
#endif
import SwiftUI
import UniformTypeIdentifiers
import VaultKit

/// Général: automatic lock delay, site icons, the import of other password managers' exports, and
/// the backup and export of the vault (encrypted backup, restore, plaintext CSV).
struct GeneralSettings: View {
    @Environment(AppModel.self) private var model
    #if os(macOS)
    @Environment(\.rxMacSettingsPage) private var inRXPage
    #endif
    @State private var importing = false
    @State private var backupSheet: BackupSheet?

    enum BackupSheet: Identifiable {
        case export, restore, plaintext
        var id: Self { self }
    }

    private var settings: VaultSettings { model.settings }
    private var shared: Bool { settings.deviceMode == .shared }

    /// Shared devices lock after 5 minutes at most: longer delays are not offered.
    private var delays: [AutoLockDelay] {
        guard shared else { return AutoLockDelay.allCases }
        return [[.immediately, .oneMinute].contains(settings.autoLockDelay) ? settings.autoLockDelay : .fiveMinutes]
    }

    var body: some View {
        // Read so the page redraws when a setting changes.
        let _ = model.settingsRevision
        Form {
            Group {
            #if os(macOS)
            // iPhone and iPad: Profil is the account row on top of Réglages; the RX Réglages of
            // the Mac window have their own Profil row.
            if !inRXPage {
                ProfileSection()
            }
            // The RX Accueil's hero: only the RX Réglages of the window dress it.
            if inRXPage {
                MacWallpaperSection()
            }
            #endif
            #if os(iOS)
            AppearanceSection()
            RXDesignSection()
            AppIconSection()
            WallpaperSection()
            #endif
            Section {
                // The label beside the menu, so the RX cards of the Mac put the menu on the
                // trailing edge (the grouped form draws it the same).
                LabeledContent("settings.general.autoLock") {
                    Picker("settings.general.autoLock", selection: Binding(
                        get: { delays.contains(settings.autoLockDelay) ? settings.autoLockDelay : .fiveMinutes },
                        set: { delay in model.updateSettings { $0.autoLockDelay = delay } }
                    )) {
                        ForEach(delays, id: \.self) { delay in
                            Text(delay.label).tag(delay)
                        }
                    }
                    .labelsHidden()
                    .fixedSize()
                    .disabled(shared)
                    .accessibilityIdentifier("settings.autoLock")
                }
                Toggle("settings.websiteIcons", isOn: Binding(
                    get: { settings.siteIconsEnabled },
                    set: { value in model.updateSettings { $0.siteIconsEnabled = value } }
                ))
                .accessibilityIdentifier("settings.siteIcons")
            } footer: {
                if shared {
                    SettingsFootnote("settings.general.autoLock.sharedFooter")
                } else {
                    SettingsFootnote("settings.general.siteIcons.footer")
                }
            }
            WifiAutoSection()
            Section {
                Button("Importer…", systemImage: "square.and.arrow.down") {
                    importing = true
                }
                .accessibilityIdentifier("settings.import")
            } footer: {
                SettingsFootnote("settings.general.import.footer")
            }
            Section {
                Button("settings.general.backup.export", systemImage: "square.and.arrow.down.on.square") {
                    backupSheet = .export
                }
                .accessibilityIdentifier("settings.backup.export")
                Button("settings.general.backup.restore", systemImage: "clock.arrow.circlepath") {
                    backupSheet = .restore
                }
                .accessibilityIdentifier("settings.backup.restore")
                Button("settings.general.backup.plaintext", systemImage: "exclamationmark.triangle") {
                    backupSheet = .plaintext
                }
                .foregroundStyle(.red)
                .accessibilityIdentifier("settings.backup.plaintext")
            } header: {
                SettingsHeader("settings.general.backup.header")
            } footer: {
                SettingsFootnote("settings.general.backup.footer")
            }
            }
            .rxSettingsRows()
        }
        .rxSettingsSkin()
        // Over the settings themselves (the Mac `Settings` window has no browse sheet).
        .sheet(isPresented: $importing) {
            ImportSheet()
        }
        .sheet(item: $backupSheet) { kind in
            switch kind {
            case .export: ExportBackupSheet()
            case .restore: RestoreSheet()
            case .plaintext: PlaintextExportSheet()
            }
        }
        .settingsPage("Général")
    }
}

/// "Wi-Fi automatique": the only control of the feature (spec 2026-11-04-wifi-auto).
private struct WifiAutoSection: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var wifi = model.wifi
        Section {
            Toggle("settings.general.wifiAuto", isOn: $wifi.enabled)
                .accessibilityIdentifier("settings.wifiAuto")
        } footer: {
            #if os(macOS)
            SettingsFootnote("settings.general.wifiAuto.footer.mac")
            #else
            SettingsFootnote("settings.general.wifiAuto.footer")
            #endif
        }
    }
}

/// iPhone and iPad: Profil, opened from the account row on top of Réglages.
struct ProfileSettings: View {
    var body: some View {
        Form {
            ProfileSection()
                .rxSettingsRows()
        }
        .rxSettingsSkin()
        .settingsPage("Profil")
    }
}

#if os(iOS)
/// Apparence: follow the system, or keep OnePass light or dark. Three small screens to pick from,
/// as in the system's Display settings. Stored on this device only.
private struct AppearanceSection: View {
    @AppStorage(Appearance.storageKey, store: AppModel.browseDefaults) private var stored = Appearance.system.rawValue

    var body: some View {
        let current = Appearance(stored: stored)
        Section {
            HStack(spacing: 0) {
                ForEach(Appearance.allCases) { appearance in
                    Button {
                        stored = appearance.rawValue
                    } label: {
                        AppearanceChoice(appearance: appearance, selected: appearance == current)
                    }
                    .buttonStyle(.plain)
                    .frame(maxWidth: .infinity)
                    .accessibilityIdentifier("settings.appearance.\(appearance.rawValue)")
                    .accessibilityAddTraits(appearance == current ? .isSelected : [])
                }
            }
            .padding(.vertical, Theme.Space.s)
            .sensoryFeedback(.selection, trigger: stored)
        } header: {
            SettingsHeader("settings.general.appearance")
        }
    }
}

/// Nouveau design: the RX look (photo heroes, grouped cards, glass buttons) on Réglages, Watchtower,
/// the item detail and Accueil. A preview, off by default, stored on this device only.
private struct RXDesignSection: View {
    @AppStorage(RXDesign.storageKey, store: AppModel.browseDefaults) private var isOn = RXDesign.launchDefault

    var body: some View {
        Section {
            Toggle("rx.settings.toggle", isOn: $isOn)
                .accessibilityIdentifier("settings.rxDesign")
        } footer: {
            SettingsFootnote("rx.settings.footer")
        }
    }
}

/// One appearance: a small screen drawn with the app's own surfaces in that appearance (half and
/// half for Automatique), its name, and the selection circle.
private struct AppearanceChoice: View {
    let appearance: Appearance
    let selected: Bool

    var body: some View {
        VStack(spacing: Theme.Space.m) {
            preview
                .frame(width: 58, height: 96)
                .overlay {
                    RoundedRectangle(cornerRadius: Theme.Radius.control, style: .continuous)
                        .strokeBorder(selected ? Theme.accent : Color.primary.opacity(0.12), lineWidth: selected ? 2 : 1)
                }
            Text(title)
                .font(.subheadline)
                .foregroundStyle(.primary)
            Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                .font(.title3)
                .foregroundStyle(selected ? Theme.accent : Color.secondary.opacity(0.6))
                .contentTransition(.symbolEffect(.replace))
        }
        .contentShape(.rect)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(title))
    }

    private var title: LocalizedStringKey {
        switch appearance {
        case .system: "settings.general.appearance.system"
        case .light: "settings.general.appearance.light"
        case .dark: "settings.general.appearance.dark"
        }
    }

    @ViewBuilder private var preview: some View {
        let shape = RoundedRectangle(cornerRadius: Theme.Radius.control, style: .continuous)
        switch appearance {
        case .system:
            ZStack {
                MiniScreen().environment(\.colorScheme, .light)
                MiniScreen().environment(\.colorScheme, .dark)
                    .mask {
                        GeometryReader { proxy in
                            Path { path in
                                path.move(to: CGPoint(x: proxy.size.width, y: 0))
                                path.addLine(to: CGPoint(x: proxy.size.width, y: proxy.size.height))
                                path.addLine(to: CGPoint(x: 0, y: proxy.size.height))
                                path.closeSubpath()
                            }
                        }
                    }
            }
            .clipShape(shape)
        case .light:
            MiniScreen().environment(\.colorScheme, .light).clipShape(shape)
        case .dark:
            MiniScreen().environment(\.colorScheme, .dark).clipShape(shape)
        }
    }
}

/// The app in miniature: the page, a title bar, two cards and a row of tiles. Its sizes are a
/// drawing at about a sixth of the screen, not the spacing scale.
private struct MiniScreen: View {
    var body: some View {
        ZStack(alignment: .top) {
            Theme.page
            VStack(alignment: .leading, spacing: 5) {
                Capsule().fill(Color.primary.opacity(0.55)).frame(width: 24, height: 4)
                    .padding(.bottom, 2)
                HStack(spacing: 4) {
                    RoundedRectangle(cornerRadius: 4, style: .continuous).fill(Theme.card).frame(height: 18)
                        .overlay(alignment: .topLeading) {
                            RoundedRectangle(cornerRadius: 2).fill(Theme.accent).frame(width: 6, height: 6).padding(3)
                        }
                    RoundedRectangle(cornerRadius: 4, style: .continuous).fill(Theme.card).frame(height: 18)
                        .overlay(alignment: .topLeading) {
                            RoundedRectangle(cornerRadius: 2).fill(.orange).frame(width: 6, height: 6).padding(3)
                        }
                }
                RoundedRectangle(cornerRadius: 4, style: .continuous).fill(Theme.card).frame(height: 30)
                    .overlay(alignment: .leading) {
                        VStack(alignment: .leading, spacing: 3) {
                            Capsule().fill(Color.primary.opacity(0.35)).frame(width: 22, height: 3)
                            Capsule().fill(Color.primary.opacity(0.2)).frame(width: 16, height: 3)
                        }
                        .padding(.leading, 5)
                    }
            }
            .padding(.horizontal, 6)
            .padding(.top, 12)
        }
    }
}
#endif

/// Profil: the account's name and photo, shown in the sidebar, the account panel and the settings.
struct ProfileSection: View {
    @Environment(AppModel.self) private var model
    @State private var choosingFile = false
    @State private var failed = false
    /// The Settings window opens on this page: the name field would take focus with all its text
    /// selected. It only focuses on a click.
    @FocusState private var nameFocused: Bool
    #if os(iOS)
    @State private var pick: PhotosPickerItem?
    #endif
    /// The RX look of Réglages on the Mac: the round RX avatar, the field in the RX field token
    /// (the iPhone keeps its own look).
    @Environment(\.rxSettings) private var rxSettings
    private var rx: Bool {
        #if os(macOS)
        rxSettings
        #else
        false
        #endif
    }

    var body: some View {
        let _ = model.settingsRevision
        Section {
            HStack(spacing: Theme.Space.l) {
                avatar
                    #if os(macOS)
                    .dropDestination(for: Data.self) { items, _ in
                        guard let data = items.first else { return false }
                        return use(data)
                    }
                    #endif
                VStack(alignment: .leading, spacing: Theme.Space.s) {
                    TextField("settings.name", text: Binding(
                        get: { model.settings.displayName },
                        set: { name in model.setProfile(name: name, photo: model.settings.profilePhoto) }
                    ), prompt: Text("settings.name2"))
                    .labelsHidden()
                    .textFieldStyle(.plain)
                    .font(rx ? Theme.RX.Typography.headline.font(size: 15) : .title3.weight(.semibold))
                    .focused($nameFocused)
                    // A real field: a soft well, an accent ring while typing.
                    .padding(.horizontal, Theme.Space.m)
                    .padding(.vertical, Theme.Space.s)
                    .background(rx ? AnyShapeStyle(Theme.RX.Palette.field.color) : AnyShapeStyle(.fill.quaternary),
                                in: .rect(cornerRadius: Theme.Radius.control, style: .continuous))
                    .overlay {
                        RoundedRectangle(cornerRadius: Theme.Radius.control, style: .continuous)
                            .strokeBorder(nameFocused ? Theme.accent : Color.primary.opacity(0.08), lineWidth: nameFocused ? 1.5 : 1)
                    }
                    .frame(maxWidth: 280, alignment: .leading)
                    .accessibilityIdentifier("settings.profile.name")
                    HStack(spacing: Theme.Space.m) {
                        #if os(iOS)
                        PhotosPicker(selection: $pick, matching: .images) {
                            Text(model.settings.profilePhoto == nil ? "Ajouter une photo…" : "Changer la photo…")
                        }
                        .accessibilityIdentifier("settings.profile.photo")
                        #else
                        Button(model.settings.profilePhoto == nil ? "Ajouter une photo…" : "Changer la photo…") {
                            choosingFile = true
                        }
                        .accessibilityIdentifier("settings.profile.photo")
                        #endif
                        if model.settings.profilePhoto != nil {
                            Button("common.remove", role: .destructive) {
                                model.setProfile(name: model.settings.displayName, photo: nil)
                            }
                            .accessibilityIdentifier("settings.profile.removePhoto")
                        }
                    }
                }
            }
            .padding(.vertical, Theme.Space.xs)
        } header: {
            // The RX Réglages of the Mac title the page Profil already.
            if !rx { SettingsHeader("Profil") }
        } footer: {
            SettingsFootnote(failed
                ? "Cette image n'a pas pu être lue. Essaie un JPEG, un PNG ou un HEIC."
                : "Synchronisé sur tes appareils, sans ses métadonnées.")
        }
        .task {
            try? await Task.sleep(for: .milliseconds(50))
            nameFocused = false
        }
        .fileImporter(isPresented: $choosingFile, allowedContentTypes: [.image]) { result in
            guard case .success(let url) = result else { return }
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            if let data = try? Data(contentsOf: url) { _ = use(data) } else { failed = true }
        }
        #if os(iOS)
        .onChange(of: pick) {
            guard let pick else { return }
            Task {
                if let data = try? await pick.loadTransferable(type: Data.self) { _ = use(data) } else { failed = true }
                self.pick = nil
            }
        }
        #endif
    }

    @ViewBuilder private var avatar: some View {
        Group {
            if rx {
                RXAvatar(initials: model.initials, photo: model.profileImage, size: 64, ring: false)
            } else {
                AccountAvatar(initials: model.initials, photo: model.profileImage, size: 64)
            }
        }
    }

    @discardableResult private func use(_ data: Data) -> Bool {
        guard let photo = ProfilePhoto.square(from: data) else {
            failed = true
            return false
        }
        failed = false
        model.setProfile(name: model.settings.displayName, photo: photo)
        return true
    }
}

/// Turns any image into the stored profile photo: a centered square of 256 px, as a JPEG written
/// from the pixels alone (EXIF, GPS and other metadata stay behind).
enum ProfilePhoto {
    static let side = 256

    static func square(from data: Data) -> Data? {
        guard let source = CGImageSourceCreateWithData(data as CFData, nil),
            let image = CGImageSourceCreateThumbnailAtIndex(source, 0, [
                kCGImageSourceCreateThumbnailFromImageAlways: true,
                kCGImageSourceCreateThumbnailWithTransform: true,
                kCGImageSourceThumbnailMaxPixelSize: side * 3,
            ] as CFDictionary)
        else { return nil }
        let edge = min(image.width, image.height)
        let crop = CGRect(x: (image.width - edge) / 2, y: (image.height - edge) / 2, width: edge, height: edge)
        guard let square = image.cropping(to: crop),
            let space = CGColorSpace(name: CGColorSpace.sRGB),
            let context = CGContext(data: nil, width: side, height: side, bitsPerComponent: 8, bytesPerRow: 0,
                space: space, bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue)
        else { return nil }
        context.interpolationQuality = .high
        context.draw(square, in: CGRect(x: 0, y: 0, width: side, height: side))
        guard let scaled = context.makeImage() else { return nil }
        let out = NSMutableData()
        guard let destination = CGImageDestinationCreateWithData(out, UTType.jpeg.identifier as CFString, 1, nil)
        else { return nil }
        CGImageDestinationAddImage(destination, scaled, [kCGImageDestinationLossyCompressionQuality: 0.85] as CFDictionary)
        return CGImageDestinationFinalize(destination) ? out as Data : nil
    }
}

// MARK: - The RX look of the pages of Réglages


/// The pages of Réglages in the RX look (owner feedback 2026-11-16: "rends les sous-pages comme le
/// reste du RX, avec moins de texte"). Each page keeps its `Form`, so every setting, sheet, swipe
/// and identifier stays as it is; while the RX look is on (iPhone), the form is drawn as RX cards:
/// the RX page colour, cards in the card token with no separators, Inter rows, card titles in
/// Headline inside the page's rhythm, footnotes in Footnote. Off, nothing changes.
///
/// Usage: `Form { Group { sections }.rxSettingsRows() }.rxSettingsSkin().settingsPage("Titre")`.
/// The skin goes before `settingsPage`, so its tint and background win over the classic ones.
extension View {
    /// The whole page (the form): page colour, gutters, section rhythm, Inter, RX accent.
    func rxSettingsSkin() -> some View {
        modifier(RXSettingsSkin())
    }

    /// The rows of every section in it: card background, no separators, RX label glyphs.
    func rxSettingsRows() -> some View {
        modifier(RXSettingsRows())
    }
}

extension EnvironmentValues {
    /// True on a page of Réglages drawn in the RX look.
    @Entry var rxSettings = false
}

private struct RXSettingsSkin: ViewModifier {
    @AppStorage(RXDesign.storageKey, store: AppModel.browseDefaults) private var rxDesign = RXDesign.launchDefault

    private typealias RX = Theme.RX

    func body(content: Content) -> some View {
        #if os(iOS)
        if rxDesign {
            content
                .rxFont(.bodyMedium)
                .listSectionSpacing(RX.Space.l)
                .contentMargins(.horizontal, RX.Space.gutter, for: .scrollContent)
                .scrollContentBackground(.hidden)
                // No colour of its own: `settingsPage` draws the frosted backdrop behind.
                .tint(RX.Palette.accentText.color)
                .environment(\.rxSettings, true)
        } else {
            content
        }
        #else
        content
        #endif
    }
}

private struct RXSettingsRows: ViewModifier {
    @Environment(\.rxSettings) private var rx

    private typealias RX = Theme.RX

    func body(content: Content) -> some View {
        if rx {
            content
                .modifier(RXFrostedRowFill())
                .listRowSeparator(.hidden)
                .labelStyle(RXSettingsLabelStyle())
        } else {
            content
        }
    }
}

/// A row's label in the RX look: the 24 pt glyph of `RXMenuRow`, then the title, which wraps.
private struct RXSettingsLabelStyle: LabelStyle {
    private typealias RX = Theme.RX

    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: RX.Space.l) {
            // Monochrome, as the rows of the frosted Réglages.
            configuration.icon
                .font(RX.Glyph.font(RX.Glyph.menu, weight: .medium))
                .foregroundStyle(RX.Palette.textPrimary.color)
                .frame(width: RX.Metrics.menuGlyph, height: RX.Metrics.menuGlyph)
                .accessibilityHidden(true)
            // Wraps at full size: no tightening or scaling, which the clipped text audit reports.
            configuration.title
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

/// A card title with the long explanation behind an info button (in place of a paragraph under
/// the card). Classic look: the same, as a section header.
struct SettingsHeader: View {
    let title: Text
    var info: Text?
    var infoID: String?
    @Environment(\.rxSettings) private var rx

    private typealias RX = Theme.RX

    init(_ title: LocalizedStringKey, info: Text? = nil, id: String? = nil) {
        self.init(Text(title), info: info, id: id)
    }

    init(_ title: Text, info: Text? = nil, id: String? = nil) {
        self.title = title
        self.info = info
        self.infoID = id
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: RX.Space.s) {
            if rx {
                title
                    .rxFont(.headline)
                    .foregroundStyle(RX.Palette.textPrimary.color)
                    .textCase(nil)
                    .dbText(maxLines: 2)
                    .accessibilityAddTraits(.isHeader)
            } else {
                title
            }
            Spacer(minLength: 0)
            if let info {
                SettingsInfoButton(info, id: infoID)
            }
        }
    }
}

/// The ⓘ that holds a long explanation: a popover on iPhone too, so it reads in place.
struct SettingsInfoButton: View {
    let text: Text
    var id: String?
    @State private var shown = false

    private typealias RX = Theme.RX

    init(_ text: Text, id: String? = nil) {
        self.text = text
        self.id = id
    }

    var body: some View {
        Button {
            shown = true
        } label: {
            Image(systemName: "info.circle")
                .font(RX.Glyph.font(RX.Glyph.menu, weight: .regular))
                .frame(minWidth: RX.Metrics.minTapTarget, minHeight: RX.Metrics.minTapTarget, alignment: .trailing)
                .contentShape(.rect)
        }
        .buttonStyle(.borderless)
        .textCase(nil)
        .accessibilityLabel(Text("settings.info"))
        .dbHaptic(.selection, trigger: shown)
        .popover(isPresented: $shown) {
            ScrollView {
                text
                    .rxFont(.callout)
                    .foregroundStyle(RX.Palette.textPrimary.color)
                    .dbText()
                    .frame(maxWidth: 320, alignment: .leading)
                    .padding(RX.Space.l)
            }
            .frame(idealWidth: 320, maxHeight: 420)
            .presentationCompactAdaptation(.popover)
            .accessibilityIdentifier("settings.info.text")
        }
        .accessibilityIdentifier(id ?? "settings.info")
    }
}

/// A short footnote under a card: RX Footnote in the tertiary text token; the system footer in the
/// classic look.
struct SettingsFootnote: View {
    let text: Text
    @Environment(\.rxSettings) private var rx

    private typealias RX = Theme.RX

    init(_ key: LocalizedStringKey) { text = Text(key) }
    init(_ text: Text) { self.text = text }

    var body: some View {
        if rx {
            text
                .rxFont(.footnote)
                .foregroundStyle(RX.Palette.textSecondary.color)
                .textCase(nil)
                .dbText()
        } else {
            text
        }
    }
}
