import DesignKit
import SwiftUI
import VaultKit

/// Appareils (spec 2b 4.3): the signed device list, "Ajouter un appareil" on iPhone and iPad (scan the
/// new device's QR), "Configurer un appareil…" on the Mac (it shows the code, the new device joins it),
/// "Retirer cet appareil" for any other device (ruling A6) after a confirmation and a fresh presence
/// check (ruling A8), then the advice to change the master password. On an account whose removals go
/// through the key lineage, a removed device can be marked stolen ("Marquer comme volé", founder
/// decision 2026-11-03): after a confirmation and the same presence check, it erases its local copy at
/// its next sync instead of 7 days later.
struct DevicesSettings: View {
    @Environment(AppModel.self) private var model
    @State private var approving = false
    #if os(macOS)
    @State private var hosting = false
    #endif
    @State private var confirmRevoke: FfiDevice?
    @State private var passwordForRevoke: DeviceTarget?
    @State private var revokedName: String?
    @State private var confirmStolen: FfiDevice?
    @State private var passwordForStolen: DeviceTarget?
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
                    DeviceRow(device: device, isThisDevice: isThisDevice(device), ack: session.rotationAcks[device.id]) {
                        deviceMenu(device)
                    }
                }
            } header: {
                Text("settings.onAccount")
            } footer: {
                VStack(alignment: .leading, spacing: Theme.Space.s) {
                    Text("settings.devices.list.footer")
                    if !session.rotationAcks.isEmpty {
                        Text("settings.devices.ack.footer")
                    }
                }
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
                // Vision Pro neither scans nor hosts (ruling A2): an iPhone or an iPad approves it.
                Label("Utilise ton iPhone ou ton iPad pour approuver un nouvel appareil.", systemImage: "iphone")
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("settings.devices.useIPhone")
                #endif
            } footer: {
                #if os(iOS)
                Text("settings.devices.add.footer")
                #elseif os(macOS)
                Text("settings.macShowsCodeTo")
                #else
                Text("settings.devices.add.footer.mac")
                #endif
            }
            if !revoked.isEmpty {
                Section("settings.removed") {
                    ForEach(revoked, id: \.id) { device in
                        DeviceRow(device: device, isThisDevice: false, ack: nil) { stolenAction(device) }
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
        .vaultRefresh { await reload() }
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
            Text("settings.remove \(confirmRevoke?.name ?? "")"),
            isPresented: Binding(get: { confirmRevoke != nil }, set: { if !$0 { confirmRevoke = nil } }),
            titleVisibility: .visible,
            presenting: confirmRevoke
        ) { device in
            Button("settings.removeDevice", role: .destructive) {
                Task { await revoke(device) }
            }
            .accessibilityIdentifier("settings.devices.revoke.confirm")
            Button("Annuler", role: .cancel) {}
        } message: { _ in
            Text("settings.itErasesOnepassData")
        }
        .confirmationDialog(
            Text("settings.markStolen \(confirmStolen?.name ?? "")"),
            isPresented: Binding(get: { confirmStolen != nil }, set: { if !$0 { confirmStolen = nil } }),
            titleVisibility: .visible,
            presenting: confirmStolen
        ) { device in
            Button("settings.devices.markStolen", role: .destructive) {
                Task { await markStolen(device) }
            }
            .accessibilityIdentifier("settings.devices.stolen.confirm")
            Button("Annuler", role: .cancel) {}
        } message: { _ in
            Text("settings.markStolen.message")
        }
        .sheet(item: $passwordForStolen) { target in
            let device = target.device
            PasswordPromptSheet(
                title: "settings.markStolen \(device.name)",
                footer: "settings.confirmWithMasterPassword"
            ) { password in
                try await session.markStolen(device.id, password: password)
            }
        }
        .sheet(item: $passwordForRevoke) { target in
            let device = target.device
            PasswordPromptSheet(
                title: "Retirer \(device.name)",
                footer: "settings.confirmWithMasterPassword"
            ) { password in
                try await session.revokeDevice(device.id, password: password)
                revokedName = device.name
            }
        }
        .alert(
            Text("settings.removed \(revokedName ?? "")"),
            isPresented: Binding(get: { revokedName != nil }, set: { if !$0 { revokedName = nil } })
        ) {
            Button("settings.changeMasterPassword") { changingPassword = true }
            Button("app.later", role: .cancel) {}
        } message: {
            Text("settings.changeMasterPasswordIf")
        }
        .alert(
            "Renommer l'appareil",
            isPresented: Binding(get: { renaming != nil }, set: { if !$0 { renaming = nil } }),
            presenting: renaming
        ) { device in
            TextField("settings.name", text: $newName)
            Button("common.rename") { Task { await rename(device) } }
            Button("Annuler", role: .cancel) {}
        }
        .sheet(isPresented: $changingPassword) {
            ChangePasswordSheet()
        }
    }

    @ViewBuilder private func deviceMenu(_ device: FfiDevice) -> some View {
        Menu {
            Button("common.rename", systemImage: "pencil") {
                newName = device.name
                renaming = device
            }
            if !isThisDevice(device) {
                Button("settings.removeDevice", systemImage: "minus.circle", role: .destructive) {
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
        .accessibilityLabel(Text("app.actionsFor \(device.name)"))
        .accessibilityIdentifier("settings.devices.menu.\(device.id)")
    }

    /// A removed device: "Marquer comme volé" while the account can, "Marqué comme volé" once done.
    @ViewBuilder private func stolenAction(_ device: FfiDevice) -> some View {
        if session.stolenDeviceIDs.contains(device.id) {
            Text("settings.stolen")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .accessibilityIdentifier("settings.devices.stolen.\(device.id)")
        } else if session.canMarkStolen {
            Button("settings.devices.markStolen", role: .destructive) {
                errorMessage = nil
                confirmStolen = device
            }
            .buttonStyle(.borderless)
            .font(.footnote)
            .accessibilityIdentifier("settings.devices.markStolen.\(device.id)")
        }
    }

    /// Face ID or Touch ID first; without them (or refused), the master password sheet.
    private func markStolen(_ device: FfiDevice) async {
        do {
            try await session.markStolen(device.id)
        } catch {
            let failure = VaultError(error)
            if failure == .passwordRequired {
                passwordForStolen = DeviceTarget(device: device)
            } else {
                errorMessage = failure.localizedMessage
            }
        }
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
/// greyed with its revocation date. After a key rotation, "À jour" or "En attente" from the device's
/// signed acknowledgment (spec 6.8, O6; display only).
private struct DeviceRow<Actions: View>: View {
    let device: FfiDevice
    let isThisDevice: Bool
    let ack: FfiDeviceAck?
    @ViewBuilder let actions: () -> Actions

    private var revokedAt: Date? { device.revokedAt.map { Date(timeIntervalSince1970: TimeInterval($0)) } }
    private var addedAt: Date { Date(timeIntervalSince1970: TimeInterval(device.addedAt)) }

    private var detail: String {
        let kind = DeviceKindText.kind(device.kind)
        let mode = DeviceKindText.mode(device.mode)
        if let revokedAt {
            return String(localized: "settings.removedOn \(kind) \(revokedAt.formatted(date: .abbreviated, time: .omitted))")
        }
        return String(localized: "settings.addedOn \(kind) \(mode) \(addedAt.formatted(date: .abbreviated, time: .omitted))")
    }

    var body: some View {
        HStack(spacing: Theme.Space.m) {
            Image(systemName: DeviceKindText.symbol(device.kind))
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(.white)
                .frame(width: 30, height: 30)
                .washBackground(
                    revokedAt == nil ? AnyShapeStyle(Theme.Wash.accent) : AnyShapeStyle(Color.gray),
                    flat: revokedAt == nil ? Theme.accent : Color.gray,
                    in: RoundedRectangle(cornerRadius: Theme.Radius.chip, style: .continuous))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                HStack(spacing: Theme.Space.s) {
                    Text(device.name).lineLimit(1)
                    if isThisDevice {
                        Text("settings.device")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(Theme.readableAccent)
                            .padding(.horizontal, Theme.Space.s)
                            .padding(.vertical, Theme.Space.xxs)
                            .background(Theme.accent.opacity(0.15), in: Capsule())
                    }
                }
                Text(detail)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                if revokedAt == nil, let ack {
                    AckLabel(acknowledged: ack.acknowledged)
                        .accessibilityIdentifier("settings.devices.ack.\(device.id)")
                }
            }
            Spacer(minLength: 0)
            if revokedAt == nil { actions() }
        }
        .opacity(revokedAt == nil ? 1 : 0.55)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("settings.devices.row.\(device.id)")
    }
}

/// "À jour" (the device confirmed the current keys) or "En attente" (spec 6.8, 9).
private struct AckLabel: View {
    let acknowledged: Bool

    var body: some View {
        Label {
            Text(acknowledged ? "settings.devices.ack.upToDate" : "settings.devices.ack.pending")
        } icon: {
            Image(systemName: acknowledged ? "checkmark.circle.fill" : "clock")
        }
        .font(.caption)
        .foregroundStyle(acknowledged ? Color.green : Color.secondary)
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
                Text("settings.notAvailableInBuild")
                    .foregroundStyle(.secondary)
            } else if bridge.paired.isEmpty {
                Label("settings.openOnepassExtensionIn",
                    systemImage: "puzzlepiece.extension")
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("settings.devices.browsers.empty")
            } else {
                ForEach(bridge.paired) { paired in
                    row(paired)
                }
            }
            ForEach(bridge.blocked, id: \.self) { extensionId in
                LabeledContent {
                    Button("Autoriser de nouveau") { bridge.allowAgain(extensionId) }
                        .accessibilityIdentifier("settings.devices.browsers.allowAgain")
                } label: {
                    Text(extensionId == "safari" ? "Safari" : extensionId).lineLimit(1)
                    Text("Oubliée : ne se reconnecte plus seule. Associe-la avec le code, ou autorise-la de nouveau.")
                }
                .accessibilityIdentifier("settings.devices.browsers.blocked")
            }
        } header: {
            Text("settings.browserExtensions")
        } footer: {
            Text("Elles se connectent seules à OnePass quand le Mac vérifie la signature du navigateur, remplissent depuis le coffre ouvert sur ce Mac et se verrouillent avec lui.")
        }
        .confirmationDialog(
            Text("settings.forget2 \(forgetting?.browser ?? "")"),
            isPresented: Binding(get: { forgetting != nil }, set: { if !$0 { forgetting = nil } }),
            titleVisibility: .visible, presenting: forgetting
        ) { paired in
            Button("settings.forgetExtension", role: .destructive) { bridge.forget(paired.id) }
                .accessibilityIdentifier("settings.devices.browsers.confirmForget")
        } message: { _ in
            Text("Elle ne pourra plus remplir ni se reconnecter seule. Pour la réutiliser, associe-la avec le code, ou autorise-la de nouveau ici.")
        }
    }

    private func row(_ paired: BrowserBridge.Paired) -> some View {
        HStack(spacing: 12) {
            Image(systemName: Self.symbol(paired.browser))
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(.white)
                .frame(width: 30, height: 30)
                .background(Self.color(paired.browser), in: RoundedRectangle(cornerRadius: Theme.Radius.chip, style: .continuous))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(paired.browser).lineLimit(1)
                    Text("settings.extension")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 7)
                        .padding(.vertical, 2)
                        .background(.fill.tertiary, in: Capsule())
                }
                Text(paired.automatic
                    ? "Associée automatiquement · utilisée \(paired.lastUsed.formatted(.relative(presentation: .named)))"
                    : "\(paired.extensionName) · utilisée \(paired.lastUsed.formatted(.relative(presentation: .named)))")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer(minLength: 0)
            Menu {
                Button("settings.forgetExtension", systemImage: "minus.circle", role: .destructive) { forgetting = paired }
            } label: {
                Image(systemName: "ellipsis.circle").font(.title3)
            }
            .menuStyle(.button)
            .buttonStyle(.borderless)
            .menuIndicator(.hidden)
            .fixedSize()
            .accessibilityLabel(Text("app.actions"))
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
