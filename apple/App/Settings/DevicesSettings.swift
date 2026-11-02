import DesignKit
import SwiftUI
import VaultKit

/// Appareils (spec 2b 4.3): the signed device list, "Ajouter un appareil" on iPhone and iPad (scan the
/// new device's QR), "Configurer un appareil…" on the Mac (it shows the code, the new device joins it),
/// "Retirer cet appareil" for any other device (ruling A6) after a confirmation and a fresh presence
/// check (ruling A8), then the advice to change the master password.
struct DevicesSettings: View {
    @Environment(AppModel.self) private var model
    @State private var approving = false
    #if os(macOS)
    @State private var hosting = false
    #endif
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
                Text("settings.devices.list.footer")
            }
            #if os(macOS)
            if let bridge = model.browserBridge {
                BrowserExtensionsSection(bridge: bridge)
            }
            #endif
            Section {
                #if os(iOS)
                Button {
                    errorMessage = nil
                    approving = true
                } label: {
                    Label("Ajouter un appareil", systemImage: "plus.viewfinder")
                }
                .accessibilityIdentifier("settings.devices.add")
                #elseif os(macOS)
                // The Mac never scans (ruling A2): it shows an invite the new device scans.
                Button {
                    errorMessage = nil
                    approving = true
                } label: {
                    Label("Configurer un appareil", systemImage: "qrcode")
                }
                .accessibilityIdentifier("settings.devices.invite")
                #else
                Button {
                    errorMessage = nil
                    hosting = true
                } label: {
                    Label("Configurer un appareil…", systemImage: "qrcode")
                }
                .accessibilityIdentifier("settings.devices.host")
                #endif
            } footer: {
                #if os(iOS)
                Text("settings.devices.add.footer")
                #elseif os(macOS)
                Text("Le Mac affiche un code à scanner avec le nouvel iPhone ou iPad, puis vous comparez un code à 6 chiffres.")
                #else
                Text("settings.devices.add.footer.mac")
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
        .settingsPage("Appareils")
        .task { await reload() }
        #if os(iOS)
        .refreshable { await reload() }
        #endif
        #if os(iOS) || os(macOS)
        .sheet(isPresented: $approving, onDismiss: { Task { await reload() } }) {
            ApproveDeviceSheet()
        }
        #elseif os(macOS)
        .sheet(isPresented: $hosting, onDismiss: { Task { await reload() } }) {
            HostDeviceSheet()
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

#if os(macOS)
/// The browser extensions paired with this Mac, listed like devices: they fill from the vault open
/// here and lock with it. Each row says which browser, when it was last used, and can be forgotten.
private struct BrowserExtensionsSection: View {
    let bridge: BrowserBridge
    @State private var forgetting: BrowserBridge.Paired?

    var body: some View {
        Section {
            if !bridge.isRunning {
                Text("Indisponible dans cette version de OnePass.")
                    .foregroundStyle(.secondary)
            } else if bridge.paired.isEmpty {
                Label("Ouvre l'extension OnePass dans Safari, Chrome ou Firefox pour l'associer à ce Mac.",
                    systemImage: "puzzlepiece.extension")
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("settings.devices.browsers.empty")
            } else {
                ForEach(bridge.paired) { paired in
                    row(paired)
                }
            }
        } header: {
            Text("Extensions de navigateur")
        } footer: {
            Text("Elles remplissent depuis le coffre ouvert sur ce Mac et se verrouillent avec lui.")
        }
        .confirmationDialog(
            Text("Oublier \(forgetting?.browser ?? "") ?"),
            isPresented: Binding(get: { forgetting != nil }, set: { if !$0 { forgetting = nil } }),
            titleVisibility: .visible, presenting: forgetting
        ) { paired in
            Button("Oublier l'extension", role: .destructive) { bridge.forget(paired.id) }
                .accessibilityIdentifier("settings.devices.browsers.confirmForget")
        } message: { _ in
            Text("Elle ne pourra plus remplir. Pour la réutiliser, associe-la de nouveau.")
        }
    }

    private func row(_ paired: BrowserBridge.Paired) -> some View {
        HStack(spacing: 12) {
            Image(systemName: Self.symbol(paired.browser))
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(.white)
                .frame(width: 30, height: 30)
                .background(Self.color(paired.browser).gradient, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(paired.browser).lineLimit(1)
                    Text("Extension")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 7)
                        .padding(.vertical, 2)
                        .background(.fill.tertiary, in: Capsule())
                }
                Text("\(paired.extensionName) · utilisée \(paired.lastUsed.formatted(.relative(presentation: .named)))")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer(minLength: 0)
            Menu {
                Button("Oublier l'extension", systemImage: "minus.circle", role: .destructive) { forgetting = paired }
            } label: {
                Image(systemName: "ellipsis.circle").font(.title3)
            }
            .menuStyle(.button)
            .buttonStyle(.borderless)
            .menuIndicator(.hidden)
            .fixedSize()
            .accessibilityLabel(Text("Actions"))
            .accessibilityIdentifier("settings.devices.browsers.menu")
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("settings.devices.browsers.row")
    }

    private static func symbol(_ browser: String) -> String {
        browser.localizedCaseInsensitiveContains("safari") ? "safari.fill" : "globe"
    }

    private static func color(_ browser: String) -> Color {
        let name = browser.lowercased()
        if name.contains("safari") { return Color(red: 0.0, green: 0.48, blue: 1.0) }
        if name.contains("firefox") { return Color(red: 0.93, green: 0.42, blue: 0.13) }
        if name.contains("chrome") { return Color(red: 0.26, green: 0.52, blue: 0.96) }
        return Color(red: 0.36, green: 0.40, blue: 0.45)
    }
}
#endif
