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
            #if os(macOS)
            // iPhone and iPad: Profil is the account row on top of Réglages.
            ProfileSection()
            #endif
            #if os(iOS)
            AppearanceSection()
            AppIconSection()
            #endif
            Section {
                Picker("settings.general.autoLock", selection: Binding(
                    get: { delays.contains(settings.autoLockDelay) ? settings.autoLockDelay : .fiveMinutes },
                    set: { delay in model.updateSettings { $0.autoLockDelay = delay } }
                )) {
                    ForEach(delays, id: \.self) { delay in
                        Text(delay.label).tag(delay)
                    }
                }
                .disabled(shared)
                .accessibilityIdentifier("settings.autoLock")
                Toggle("settings.websiteIcons", isOn: Binding(
                    get: { settings.siteIconsEnabled },
                    set: { value in model.updateSettings { $0.siteIconsEnabled = value } }
                ))
                .accessibilityIdentifier("settings.siteIcons")
            } footer: {
                if shared {
                    Text("settings.general.autoLock.sharedFooter")
                } else {
                    Text("settings.general.siteIcons.footer")
                }
            }
            WifiAutoSection()
            Section {
                Button("Importer…", systemImage: "square.and.arrow.down") {
                    importing = true
                }
                .accessibilityIdentifier("settings.import")
            } footer: {
                Text("settings.general.import.footer")
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
                Text("settings.general.backup.header")
            } footer: {
                Text("settings.general.backup.footer")
            }
        }
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
            Text("settings.general.wifiAuto.footer.mac")
            #else
            Text("settings.general.wifiAuto.footer")
            #endif
        }
    }
}

/// iPhone and iPad: Profil, opened from the account row on top of Réglages.
struct ProfileSettings: View {
    var body: some View {
        Form {
            ProfileSection()
        }
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
            .padding(.vertical, 8)
            .sensoryFeedback(.selection, trigger: stored)
        } header: {
            Text("settings.general.appearance")
        }
    }
}

/// One appearance: a small screen drawn with the app's own surfaces in that appearance (half and
/// half for Automatique), its name, and the selection circle.
private struct AppearanceChoice: View {
    let appearance: Appearance
    let selected: Bool

    var body: some View {
        VStack(spacing: 10) {
            preview
                .frame(width: 58, height: 96)
                .overlay {
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
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
        let shape = RoundedRectangle(cornerRadius: 12, style: .continuous)
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

/// The app in miniature: the page, a title bar, two cards and a row of tiles.
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

    var body: some View {
        let _ = model.settingsRevision
        Section {
            HStack(spacing: 16) {
                AccountAvatar(initials: model.initials, photo: model.profileImage, size: 64)
                    #if os(macOS)
                    .dropDestination(for: Data.self) { items, _ in
                        guard let data = items.first else { return false }
                        return use(data)
                    }
                    #endif
                VStack(alignment: .leading, spacing: 6) {
                    TextField("settings.name", text: Binding(
                        get: { model.settings.displayName },
                        set: { name in model.setProfile(name: name, photo: model.settings.profilePhoto) }
                    ), prompt: Text("settings.name2"))
                    .labelsHidden()
                    .textFieldStyle(.plain)
                    .font(.title3.weight(.semibold))
                    .focused($nameFocused)
                    // A real field: a soft well, an accent ring while typing.
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(.fill.quaternary, in: .rect(cornerRadius: 8, style: .continuous))
                    .overlay {
                        RoundedRectangle(cornerRadius: 8, style: .continuous)
                            .strokeBorder(nameFocused ? Theme.accent : Color.primary.opacity(0.08), lineWidth: nameFocused ? 1.5 : 1)
                    }
                    .frame(maxWidth: 280, alignment: .leading)
                    .accessibilityIdentifier("settings.profile.name")
                    HStack(spacing: 12) {
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
            .padding(.vertical, 4)
        } header: {
            Text("Profil")
        } footer: {
            Text(failed
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
