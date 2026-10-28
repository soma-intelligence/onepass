import DesignKit
import SwiftUI
import VaultKit

/// Appareils (spec 2b 4.3): the signed device list, "Ajouter un appareil" on iPhone and iPad (the Mac
/// and Vision Pro are added, they do not approve, ruling A2), "Retirer cet appareil" for any other
/// device (ruling A6) after a confirmation and a fresh presence check (ruling A8), then the advice to
/// change the master password.
struct DevicesSettings: View {
    @Environment(AppModel.self) private var model
    @State private var approving = false
    @State private var confirmRevoke: FfiDevice?
    @State private var passwordForRevoke: DeviceTarget?
    @State private var revokedName: String?
    @State private var changingPassword = false
    @State private var renaming: FfiDevice?
    @State private var newName = ""
    @State private var errorMessage: String?

    private var session: VaultSession { model.session }

    private var active: [FfiDevice] {
        session.devices
            .filter { $0.revokedAt == nil }
            .sorted { a, b in
                if isThisDevice(a) != isThisDevice(b) { return isThisDevice(a) }
                return a.addedAt < b.addedAt
            }
    }

    private var revoked: [FfiDevice] {
        session.devices.filter { $0.revokedAt != nil }.sorted { ($0.revokedAt ?? 0) > ($1.revokedAt ?? 0) }
    }

    private func isThisDevice(_ device: FfiDevice) -> Bool {
        device.isThisDevice || device.id == session.thisDeviceID
    }

    var body: some View {
        Form {
            Section {
                ForEach(active, id: \.id) { device in
                    DeviceRow(device: device, isThisDevice: isThisDevice(device)) {
                        deviceMenu(device)
                    }
                }
            } header: {
                Text("Sur ton compte")
            } footer: {
                Text("Cette liste est signée par ton compte : le serveur ne peut ni ajouter ni cacher un appareil.")
            }
            Section {
                #if os(iOS)
                Button {
                    errorMessage = nil
                    approving = true
                } label: {
                    Label("Ajouter un appareil", systemImage: "plus.viewfinder")
                }
                .accessibilityIdentifier("settings.devices.add")
                #else
                Label("Utilise ton iPhone ou ton iPad pour approuver un nouvel appareil.", systemImage: "iphone")
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("settings.devices.useIPhone")
                #endif
            } footer: {
                #if os(iOS)
                Text("Sur le nouvel appareil, choisis « J'ai déjà OnePass sur un autre appareil » : il affiche un QR code à scanner d'ici.")
                #else
                // The Mac never scans (ruling A2): the QR code is scanned from the iPhone or the iPad.
                Text("Sur le nouvel appareil, choisis « J'ai déjà OnePass sur un autre appareil » : il affiche un QR code à scanner avec ton iPhone ou ton iPad.")
                #endif
            }
            if !revoked.isEmpty {
                Section("Retirés") {
                    ForEach(revoked, id: \.id) { device in
                        DeviceRow(device: device, isThisDevice: false) { EmptyView() }
                    }
                }
            }
            if let errorMessage {
                Section {
                    Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                        .accessibilityIdentifier("settings.devices.error")
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Appareils")
        #if os(iOS) || os(visionOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
        .task { await reload() }
        #if os(iOS)
        .refreshable { await reload() }
        .sheet(isPresented: $approving, onDismiss: { Task { await reload() } }) {
            ApproveDeviceSheet()
        }
        #endif
        .confirmationDialog(
            Text("Retirer \(confirmRevoke?.name ?? "") ?"),
            isPresented: Binding(get: { confirmRevoke != nil }, set: { if !$0 { confirmRevoke = nil } }),
            titleVisibility: .visible,
            presenting: confirmRevoke
        ) { device in
            Button("Retirer cet appareil", role: .destructive) {
                Task { await revoke(device) }
            }
            .accessibilityIdentifier("settings.devices.revoke.confirm")
            Button("Annuler", role: .cancel) {}
        } message: { _ in
            Text("Il efface ses données OnePass dès qu'il voit la liste des appareils. Tu pourras l'ajouter de nouveau plus tard.")
        }
        .sheet(item: $passwordForRevoke) { target in
            let device = target.device
            PasswordPromptSheet(
                title: "Retirer \(device.name)",
                footer: "Confirme avec ton mot de passe maître pour retirer cet appareil."
            ) { password in
                try await session.revokeDevice(device.id, password: password)
                revokedName = device.name
            }
        }
        .alert(
            Text("\(revokedName ?? "") est retiré"),
            isPresented: Binding(get: { revokedName != nil }, set: { if !$0 { revokedName = nil } })
        ) {
            Button("Changer le mot de passe maître") { changingPassword = true }
            Button("Plus tard", role: .cancel) {}
        } message: {
            Text("Change ton mot de passe maître si cet appareil a été perdu ou volé.")
        }
        .alert(
            "Renommer l'appareil",
            isPresented: Binding(get: { renaming != nil }, set: { if !$0 { renaming = nil } }),
            presenting: renaming
        ) { device in
            TextField("Nom", text: $newName)
            Button("Renommer") { Task { await rename(device) } }
            Button("Annuler", role: .cancel) {}
        }
        .sheet(isPresented: $changingPassword) {
            ChangePasswordSheet()
        }
    }

    @ViewBuilder private func deviceMenu(_ device: FfiDevice) -> some View {
        Menu {
            Button("Renommer", systemImage: "pencil") {
                newName = device.name
                renaming = device
            }
            if !isThisDevice(device) {
                Button("Retirer cet appareil", systemImage: "minus.circle", role: .destructive) {
                    errorMessage = nil
                    confirmRevoke = device
                }
                .accessibilityIdentifier("settings.devices.revoke.\(device.id)")
            }
        } label: {
            Image(systemName: "ellipsis.circle")
                .foregroundStyle(.secondary)
                .frame(width: 32, height: 32)
                .contentShape(.rect)
        }
        .menuStyle(.button)
        .buttonStyle(.borderless)
        .menuIndicator(.hidden)
        .fixedSize()
        .accessibilityLabel(Text("Actions pour \(device.name)"))
        .accessibilityIdentifier("settings.devices.menu.\(device.id)")
    }

    private func reload() async {
        do {
            try await session.refreshDevices()
        } catch {
            errorMessage = VaultError(error).localizedMessage
        }
    }

    /// Face ID or Touch ID first; without them (or refused), the master password sheet.
    private func revoke(_ device: FfiDevice) async {
        do {
            try await session.revokeDevice(device.id)
            revokedName = device.name
        } catch {
            let failure = VaultError(error)
            if failure == .passwordRequired {
                passwordForRevoke = DeviceTarget(device: device)
            } else {
                errorMessage = failure.localizedMessage
            }
        }
    }

    private func rename(_ device: FfiDevice) async {
        let name = newName.trimmingCharacters(in: .whitespacesAndNewlines)
        renaming = nil
        guard !name.isEmpty, name != device.name else { return }
        do {
            try await session.renameDevice(device.id, name: String(name.prefix(64)))
        } catch {
            errorMessage = VaultError(error).localizedMessage
        }
    }
}

/// A device of the list: its kind, name, mode and date; "Cet appareil" for this one; a revoked one
/// greyed with its revocation date.
private struct DeviceRow<Actions: View>: View {
    let device: FfiDevice
    let isThisDevice: Bool
    @ViewBuilder let actions: () -> Actions

    private var revokedAt: Date? { device.revokedAt.map { Date(timeIntervalSince1970: TimeInterval($0)) } }
    private var addedAt: Date { Date(timeIntervalSince1970: TimeInterval(device.addedAt)) }

    private var detail: String {
        let kind = DeviceKindText.kind(device.kind)
        let mode = DeviceKindText.mode(device.mode)
        if let revokedAt {
            return String(localized: "\(kind) · Retiré le \(revokedAt.formatted(date: .abbreviated, time: .omitted))")
        }
        return String(localized: "\(kind) · \(mode) · ajouté le \(addedAt.formatted(date: .abbreviated, time: .omitted))")
    }

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: DeviceKindText.symbol(device.kind))
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(.white)
                .frame(width: 30, height: 30)
                .background(
                    (revokedAt == nil ? Theme.accent : Color.gray).gradient,
                    in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(device.name).lineLimit(1)
                    if isThisDevice {
                        Text("Cet appareil")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(Theme.readableAccent)
                            .padding(.horizontal, 7)
                            .padding(.vertical, 2)
                            .background(Theme.accent.opacity(0.15), in: Capsule())
                    }
                }
                Text(detail)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
            if revokedAt == nil { actions() }
        }
        .opacity(revokedAt == nil ? 1 : 0.55)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("settings.devices.row.\(device.id)")
    }
}

/// A device as the item of a sheet.
private struct DeviceTarget: Identifiable {
    let device: FfiDevice
    var id: String { device.id }
}
