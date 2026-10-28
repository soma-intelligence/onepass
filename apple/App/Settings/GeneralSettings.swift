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
        shared ? [settings.autoLockDelay == .oneMinute ? .oneMinute : .fiveMinutes] : AutoLockDelay.allCases
    }

    var body: some View {
        // Read so the page redraws when a setting changes.
        let _ = model.settingsRevision
        Form {
            ProfileSection()
            Section {
                Picker("Verrouillage automatique", selection: Binding(
                    get: { delays.contains(settings.autoLockDelay) ? settings.autoLockDelay : .fiveMinutes },
                    set: { delay in model.updateSettings { $0.autoLockDelay = delay } }
                )) {
                    ForEach(delays, id: \.self) { delay in
                        Text(delay.label).tag(delay)
                    }
                }
                .disabled(shared)
                .accessibilityIdentifier("settings.autoLock")
            } footer: {
                if shared {
                    Text("Appareil partagé : le délai est imposé (5 minutes au plus). Repasse en mode personnel pour le régler.")
                } else {
                    Text("OnePass se verrouille après ce délai d'inactivité et quand l'app reste en arrière-plan aussi longtemps.")
                }
            }
            Section {
                Toggle("Icônes des sites", isOn: Binding(
                    get: { settings.siteIconsEnabled },
                    set: { value in model.updateSettings { $0.siteIconsEnabled = value } }
                ))
                .accessibilityIdentifier("settings.siteIcons")
            } footer: {
                Text("Récupérées directement sur le site de l'élément, sans cookies et sans service tiers. Désactivées, aucune requête n'est envoyée.")
            }
            Section {
                Button("Importer depuis un autre gestionnaire…", systemImage: "square.and.arrow.down") {
                    importing = true
                }
                .accessibilityIdentifier("settings.import")
            } header: {
                Text("Import")
            } footer: {
                Text("Mots de passe d'Apple, 1Password, Bitwarden, NordPass, Dashlane, LastPass, Proton Pass, Keeper, Enpass, RoboForm, KeePass et les navigateurs.")
            }
            Section {
                Button("Exporter une sauvegarde chiffrée…", systemImage: "square.and.arrow.down.on.square") {
                    backupSheet = .export
                }
                .accessibilityIdentifier("settings.backup.export")
                Button("Restaurer une sauvegarde…", systemImage: "clock.arrow.circlepath") {
                    backupSheet = .restore
                }
                .accessibilityIdentifier("settings.backup.restore")
                Button("Exporter en CSV non chiffré…", systemImage: "exclamationmark.triangle") {
                    backupSheet = .plaintext
                }
                .foregroundStyle(.red)
                .accessibilityIdentifier("settings.backup.plaintext")
            } header: {
                Text("Sauvegarde et export")
            } footer: {
                Text("La sauvegarde chiffrée s'ouvre avec ton compte, dont la signature est vérifiée, ou avec sa phrase de passe. Restaurer n'écrase rien. Le CSV non chiffré sert seulement à passer à un autre gestionnaire.")
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
        .formStyle(.grouped)
        .navigationTitle("Général")
        #if os(iOS) || os(visionOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
    }
}

/// Profil: the account's name and photo, shown in the sidebar, the account menu and the settings.
private struct ProfileSection: View {
    @Environment(AppModel.self) private var model
    @State private var choosingFile = false
    @State private var failed = false
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
                    TextField("Nom", text: Binding(
                        get: { model.settings.displayName },
                        set: { name in model.updateSettings { $0.displayName = name } }
                    ), prompt: Text("Ton nom"))
                    .labelsHidden()
                    .textFieldStyle(.plain)
                    .font(.title3.weight(.semibold))
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
                            Button("Retirer", role: .destructive) {
                                model.updateSettings { $0.profilePhoto = nil }
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
                : "La photo reste sur cet appareil, recadrée en carré, sans ses métadonnées (lieu, date).")
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
        model.updateSettings { $0.profilePhoto = photo }
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
