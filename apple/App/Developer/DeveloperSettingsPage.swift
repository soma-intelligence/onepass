#if os(macOS)
import AppKit
import DesignKit
import SwiftUI
import UniformTypeIdentifiers
import VaultKit

/// Réglages > Développeur (Mac): the SSH agent and the MCP server the app serves on its own vaults,
/// with approval at every use, Touch ID, the paired clients, the live grants and the audit log
/// (spec 2026-10-27-m7-app, sections 3 and 4); the iPhone that approves and unlocks for the agents,
/// and the one-click install into an MCP client (agent-ready spec 7 and 8).
struct DeveloperSettingsPage: View {
    @Environment(AppModel.self) private var model
    @State private var keys: [FfiAgentKey] = []
    @State private var policy: FfiMcpPolicy?
    @State private var clients: [FfiPairedClient] = []
    @State private var grants: [FfiGrant] = []
    @State private var errorMessage: String?
    @State private var newKey = false
    /// The phone "Déverrouiller depuis mon iPhone" enrolls when several are listed.
    @State private var unlockTarget: String?

    private var hosts: DeveloperHosts { model.developer }
    private var phones: PhoneApprovals { model.phoneApprovals }
    private var installer: AgentInstaller { model.agentInstaller }
    private var dir: String { hosts.dataDirectory }

    var body: some View {
        Form {
            sshSection
            sshKeysSection
            mcpSection
            if hosts.settings.mcpEnabled {
                exposedSection
                agentFillSection
                clientsSection
                grantsSection
            }
            phoneSection
            installSection
            Section {
                NavigationLink {
                    AuditLogView()
                } label: {
                    Label("developer.auditLog", systemImage: "list.bullet.rectangle")
                }
                .accessibilityIdentifier("settings.developer.audit")
            } footer: {
                Text("developer.everySshSignatureAnd")
            }
            if let errorMessage {
                Section {
                    Label(errorMessage, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Développeur")
        .task(id: hosts.revision) { await reload() }
        .task { await phones.refreshAndWire() }
        .sheet(isPresented: $newKey, onDismiss: { Task { await reload() } }) {
            SSHKeySheet()
        }
    }

    // MARK: - SSH

    @ViewBuilder private var sshSection: some View {
        Section {
            Toggle(isOn: setting(\.sshEnabled)) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("app.sshAgent")
                    statusLine(running: hosts.sshRunning, error: hosts.sshError, enabled: hosts.settings.sshEnabled)
                }
            }
            .accessibilityIdentifier("settings.developer.ssh")
            if hosts.settings.sshEnabled {
                Toggle("developer.touchIdAtEvery", isOn: setting(\.sshRequirePresence))
                    .accessibilityIdentifier("settings.developer.sshPresence")
                Toggle("developer.allowForwardedConnections", isOn: setting(\.sshAllowForwarded))
                LabeledContent("developer.knownHosts") {
                    HStack {
                        Text(hosts.settings.knownHostsBookmark == nil ? "Non choisi" : "Choisi")
                            .foregroundStyle(.secondary)
                        Button(hosts.settings.knownHostsBookmark == nil ? "Choisir…" : "Changer…") { chooseKnownHosts() }
                        if hosts.settings.knownHostsBookmark != nil {
                            Button("common.remove") { update { $0.knownHostsBookmark = nil } }
                        }
                    }
                }
                VStack(alignment: .leading, spacing: 8) {
                    Text("developer.inSshConfig").font(.callout)
                    CodeBox(code: "Host *\n  \(hosts.paths.identityAgentLine)", onCopy: copy)
                    Text("developer.orInTerminal").font(.callout)
                    CodeBox(code: hosts.paths.exportLine, onCopy: copy)
                }
                .padding(.vertical, 4)
            }
        } header: {
            Text("app.sshAgent")
        } footer: {
            Text("developer.appServesSshKeys")
        }
    }

    @ViewBuilder private var sshKeysSection: some View {
        Section {
            if keys.isEmpty {
                Text("developer.noKeyOfferedTo")
                    .foregroundStyle(.secondary)
            }
            ForEach(keys, id: \.itemId) { key in
                HStack(spacing: 12) {
                    CategoryTile(category: .of(.sshKey), size: 28)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(key.title)
                        Text("\(key.vaultName) · \(key.fingerprint)")
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        if !key.hosts.isEmpty {
                            Text(key.hosts.joined(separator: ", ")).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    Spacer(minLength: 0)
                    Button {
                        copy(key.publicKey)
                    } label: {
                        Image(systemName: "doc.on.doc")
                    }
                    .buttonStyle(.borderless)
                    .help(Text("developer.copyPublicKey"))
                    .accessibilityLabel(Text("developer.copyPublicKeyOf \(key.title)"))
                }
            }
            Button {
                newKey = true
            } label: {
                Label("developer.newSshKey2", systemImage: "plus")
            }
            .accessibilityIdentifier("settings.developer.newKey")
        } header: {
            Text("developer.offeredKeys")
        }
    }

    // MARK: - MCP

    @ViewBuilder private var mcpSection: some View {
        Section {
            Toggle(isOn: setting(\.mcpEnabled)) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("app.mcpServer")
                    statusLine(running: hosts.mcpRunning, error: hosts.mcpError, enabled: hosts.settings.mcpEnabled)
                }
            }
            .accessibilityIdentifier("settings.developer.mcp")
            if hosts.settings.mcpEnabled {
                VStack(alignment: .leading, spacing: 8) {
                    Text("developer.toAddOnepassTo")
                        .font(.callout)
                    CodeBox(code: hosts.paths.mcpClientConfig, onCopy: copy)
                }
                .padding(.vertical, 4)
            }
        } header: {
            Text("app.mcpServer")
        } footer: {
            Text("developer.pairedAiAgentSees")
        }
    }

    @ViewBuilder private var exposedSection: some View {
        Section {
            if let policy {
                ForEach(policy.vaults, id: \.vaultId) { vault in
                    HStack {
                        Text(vault.name)
                        Spacer()
                        ScopeMenu(selected: exposed(vault) ? vault.scopes : []) { scopes in
                            Task { await setExposure(vault, scopes: scopes) }
                        }
                    }
                    .accessibilityIdentifier("settings.developer.expose.\(vault.vaultId)")
                }
                Toggle("developer.passwordGeneration", isOn: Binding(
                    get: { policy.allowGenerate },
                    set: { allow in Task { await savePolicy(allowGenerate: allow) } }))
            }
        } header: {
            Text("developer.exposedVaults")
        } footer: {
            Text("developer.nothingExposedUntilChoose")
        }
    }

    /// Agent web fill (`fill_in_browser`), vault by vault, off by default (spec 4 of the agent browser
    /// fill design). Only exposed vaults can be turned on.
    @ViewBuilder private var agentFillSection: some View {
        if let policy, policy.vaults.contains(where: exposed) {
            Section {
                ForEach(policy.vaults.filter(exposed), id: \.vaultId) { vault in
                    Toggle(vault.name, isOn: Binding(
                        get: { vault.scopes.contains("fill") },
                        set: { on in Task { await setAgentFill(vault, on: on) } }))
                        .accessibilityIdentifier("settings.developer.fill.\(vault.vaultId)")
                }
            } header: {
                Text("developer.agentWebFill")
            } footer: {
                VStack(alignment: .leading, spacing: 4) {
                    Text("developer.agentWebFillFooter")
                    Text("developer.agentWebFillTip")
                }
            }
        }
    }

    @ViewBuilder private var clientsSection: some View {
        Section {
            if clients.isEmpty {
                Text("developer.noPairedClientSigned")
                    .foregroundStyle(.secondary)
            }
            ForEach(clients, id: \.id) { client in
                DisclosureGroup {
                    ForEach(policy?.vaults.filter(exposed) ?? [], id: \.vaultId) { vault in
                        HStack {
                            Text(vault.name)
                            Spacer()
                            ScopeMenu(
                                selected: client.scopes.first { $0.vaultId == vault.vaultId }?.scopes ?? [],
                                offersFill: vault.scopes.contains("fill")
                            ) { scopes in
                                Task { await setClientScopes(client, vault: vault, scopes: scopes) }
                            }
                        }
                    }
                    Button("developer.unpair", role: .destructive) { Task { await unpair(client) } }
                } label: {
                    VStack(alignment: .leading, spacing: 1) {
                        Text(client.label)
                        Text(client.signed ? "Signé · \(client.id)" : "Non signé · \(client.id)")
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                }
            }
            Button {
                pairProgram()
            } label: {
                Label("developer.pairProgram", systemImage: "plus")
            }
        } header: {
            Text("developer.pairedClients")
        } footer: {
            Text("developer.programNotSignedBy")
        }
    }

    @ViewBuilder private var grantsSection: some View {
        Section {
            if grants.isEmpty {
                Text("developer.noActiveGrant").foregroundStyle(.secondary)
            }
            ForEach(grants, id: \.id) { grant in
                HStack {
                    VStack(alignment: .leading, spacing: 1) {
                        Text(grant.action)
                        Text("developer.until \(label(of: grant.clientId)) \(Date(timeIntervalSince1970: TimeInterval(grant.expiresAt)).formatted(date: .omitted, time: .shortened))")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("developer.revoke") { Task { await revoke(grant.id) } }
                }
            }
            if !grants.isEmpty {
                Button("developer.revokeAll", role: .destructive) { Task { await revoke(nil) } }
            }
        } header: {
            Text("developer.activeGrants")
        }
    }

    // MARK: - iPhone

    @ViewBuilder private var phoneSection: some View {
        Section {
            CardHeading(
                symbol: "iphone", color: .blue, title: String(localized: "iPhone"),
                message: String(localized: "developer.approveAgentsRequestsOn"))
            if !phones.available {
                Text("developer.buildOfOnepassDoesnt")
                    .foregroundStyle(.secondary)
            } else if phones.phones.isEmpty {
                Text("developer.noIphoneEnrolledOn")
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("settings.developer.noPhone")
            } else {
                ForEach(phones.phones) { phone in
                    Label {
                        VStack(alignment: .leading, spacing: 1) {
                            Text(phone.name)
                            Group {
                                if phone.id == phones.unlockPhone {
                                    Text("developer.approvalsAndUnlock")
                                } else {
                                    Text("developer.approvals")
                                }
                            }
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        }
                    } icon: {
                        Image(systemName: "iphone")
                    }
                    .accessibilityIdentifier("settings.developer.phone.\(phone.id)")
                }
                Toggle("developer.alsoApproveOnIphone", isOn: Binding(
                    get: { phones.approveOnPhone },
                    set: { on in Task { await phones.setApproveOnPhone(on) } }))
                    .accessibilityIdentifier("settings.developer.phoneApprovals")
                if phones.phones.count > 1, phones.unlockPhone == nil {
                    Picker("developer.iphoneUnlocks", selection: Binding(
                        get: { unlockTarget ?? phones.phones.first?.id },
                        set: { unlockTarget = $0 })) {
                        ForEach(phones.phones) { Text($0.name).tag(Optional($0.id)) }
                    }
                }
                Toggle(isOn: Binding(
                    get: { phones.unlockPhone != nil },
                    set: { on in Task { await phones.setUnlockFromPhone(on, phone: unlockTarget) } })
                ) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("developer.unlockFromMyIphone")
                        Text("developer.touchIdConfirmsOpened")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .disabled(phones.busy)
                .accessibilityIdentifier("settings.developer.phoneUnlock")
                if let code = phones.pairingCode {
                    Label("developer.onIphoneCheckCode \(code)", systemImage: "checkmark.shield")
                        .font(.callout)
                }
                Picker("developer.agentWindowLength", selection: Binding(
                    get: { phones.windowMinutes },
                    set: { minutes in Task { await phones.setWindowMinutes(minutes) } })) {
                    ForEach(PhoneApprovals.windowChoices, id: \.self) { Text(Self.duration($0)).tag($0) }
                }
                .accessibilityIdentifier("settings.developer.window")
                if let failure = phones.lastFailure {
                    Label(failure, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                }
            }
            if let message = phones.errorMessage {
                Label(message, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
            }
        } footer: {
            Text("developer.eachRequestAlsoGoes")
        }
        .accessibilityIdentifier("settings.developer.phoneCard")
    }

    /// "15 min", "1 h", "8 h".
    private static func duration(_ minutes: Int) -> String {
        minutes < 60 ? "\(minutes) min" : "\(minutes / 60) h"
    }

    // MARK: - Install

    @ViewBuilder private var installSection: some View {
        @Bindable var installer = installer
        Section {
            CardHeading(
                symbol: "square.and.arrow.down.on.square", color: .purple,
                title: String(localized: "developer.installInAgent"),
                message: String(localized: "developer.commandAddsOnlyOnepass"))
            Picker("Client", selection: $installer.client) {
                ForEach(AgentClient.allCases) { Text($0.title).tag($0) }
            }
            .accessibilityIdentifier("settings.developer.installClient")
            VStack(alignment: .leading, spacing: 8) {
                Text("developer.inTerminal").font(.callout)
                CodeBox(code: installer.terminalCommand, onCopy: copy)
                    .accessibilityIdentifier("settings.developer.installCommand")
            }
            .padding(.vertical, 4)
            // Secondary: the app's sandbox usually keeps the helper out of the client's file.
            HStack {
                Button("developer.showChanges") { Task { await installer.previewInstall() } }
                    .accessibilityIdentifier("settings.developer.installPreview")
                Button("developer.install") { Task { await installer.install() } }
                    .disabled(!installer.canInstall)
                    .accessibilityIdentifier("settings.developer.install")
                if installer.running { ProgressView().controlSize(.small) }
            }
            .disabled(installer.running)
            if let shown = installer.result ?? installer.preview, shown.blockedBySandbox {
                Label("developer.appSandboxBlocksAccess", systemImage: "lock.shield")
                    .foregroundStyle(.orange)
                    .accessibilityIdentifier("settings.developer.installSandbox")
            } else if let result = installer.result {
                if result.succeeded {
                    Label("developer.installedQuitThenOpen \(installer.client.title)", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                } else {
                    Label("developer.installationFailed", systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                }
                if !result.output.isEmpty { CodeBox(code: result.output, onCopy: copy) }
            } else if let preview = installer.preview {
                if preview.succeeded {
                    Text("developer.plannedChanges").font(.callout)
                } else {
                    Text("developer.previewFailed").font(.callout)
                }
                CodeBox(code: preview.output.isEmpty ? String(localized: "developer.noChanges") : preview.output, onCopy: copy)
            }
        } footer: {
            Text("developer.quitClientBeforeInstall")
        }
        .accessibilityIdentifier("settings.developer.installCard")
    }

    // MARK: - Pieces

    @ViewBuilder private func statusLine(running: Bool, error: String?, enabled: Bool) -> some View {
        if let error {
            Text(error).font(.caption).foregroundStyle(.orange)
        } else if running {
            Text("developer.running").font(.caption).foregroundStyle(.green)
        } else if enabled {
            Text("developer.starting").font(.caption).foregroundStyle(.secondary)
        } else {
            Text("developer.stopped").font(.caption).foregroundStyle(.secondary)
        }
    }

    private func exposed(_ vault: FfiMcpVault) -> Bool {
        vault.mcpAccess && !vault.scopes.isEmpty
    }

    private func label(of clientID: String) -> String {
        clients.first { $0.id == clientID }?.label ?? clientID
    }

    private func setting(_ key: WritableKeyPath<DeveloperSettings, Bool>) -> Binding<Bool> {
        Binding {
            hosts.settings[keyPath: key]
        } set: { value in
            update { $0[keyPath: key] = value }
        }
    }

    private func update(_ change: @escaping (inout DeveloperSettings) -> Void) {
        Task { await hosts.update(change, session: model.session) }
    }

    private func copy(_ text: String) {
        model.session.copy(text, concealed: false)
        model.showToast(String(localized: "common.copied"))
    }

    private func reload() async {
        let session = model.session
        let dir = dir
        keys = (try? await session.agentKeys()) ?? []
        guard hosts.settings.mcpEnabled else { return }
        do {
            policy = try await session.mcpPolicy(dataDirectory: dir)
            clients = try await session.pairedClients(dataDirectory: dir)
            grants = try await session.liveGrants(dataDirectory: dir)
        } catch {
            errorMessage = VaultError(error).localizedMessage
        }
    }

    private func confirmed(_ reason: String) async -> Bool {
        await SystemPresenceChecker().confirm(prompt: reason)
    }

    private func setExposure(_ vault: FfiMcpVault, scopes: [String]) async {
        let widening = Set(scopes).subtracting(exposed(vault) ? vault.scopes : []).isEmpty == false
        if widening, !(await confirmed(String(localized: "developer.exposeToAiAgents \(vault.name)"))) { return }
        do {
            // The vault's own flag and the signed policy: both are needed (spec 4.4).
            if let current = model.session.allVaults.first(where: { $0.id == vault.vaultId }),
                current.meta.mcpAccess != !scopes.isEmpty
            {
                var meta = current.meta
                meta.mcpAccess = !scopes.isEmpty
                try await model.session.updateVault(id: vault.vaultId, meta: meta)
            }
            var entries = (policy?.vaults ?? []).filter(exposed).map { FfiClientScopes(vaultId: $0.vaultId, scopes: $0.scopes) }
            entries.removeAll { $0.vaultId == vault.vaultId }
            if !scopes.isEmpty { entries.append(FfiClientScopes(vaultId: vault.vaultId, scopes: scopes)) }
            try await model.session.setMcpPolicy(dataDirectory: dir, vaults: entries, allowGenerate: policy?.allowGenerate ?? true)
            errorMessage = nil
        } catch {
            errorMessage = VaultError(error).localizedMessage
        }
        await reload()
    }

    private func setAgentFill(_ vault: FfiMcpVault, on: Bool) async {
        if on, !(await confirmed(String(localized: "developer.exposeToAiAgents \(vault.name)"))) { return }
        do {
            try await model.session.setAgentFill(dataDirectory: dir, vaultID: vault.vaultId, on: on)
            errorMessage = nil
        } catch {
            errorMessage = VaultError(error).localizedMessage
        }
        await reload()
    }

    private func savePolicy(allowGenerate: Bool) async {
        let entries = (policy?.vaults ?? []).filter(exposed).map { FfiClientScopes(vaultId: $0.vaultId, scopes: $0.scopes) }
        do {
            try await model.session.setMcpPolicy(dataDirectory: dir, vaults: entries, allowGenerate: allowGenerate)
        } catch {
            errorMessage = VaultError(error).localizedMessage
        }
        await reload()
    }

    private func setClientScopes(_ client: FfiPairedClient, vault: FfiMcpVault, scopes: [String]) async {
        let before = Set(client.scopes.first { $0.vaultId == vault.vaultId }?.scopes ?? [])
        if !Set(scopes).subtracting(before).isEmpty,
            !(await confirmed(String(localized: "developer.giveMoreRightsTo \(client.label)")))
        {
            return
        }
        do {
            try await model.session.setClientScopes(dataDirectory: dir, clientID: client.id, vaultID: vault.vaultId, scopes: scopes)
        } catch {
            errorMessage = VaultError(error).localizedMessage
        }
        await reload()
    }

    private func unpair(_ client: FfiPairedClient) async {
        do {
            try await model.session.unpairClient(dataDirectory: dir, clientID: client.id)
        } catch {
            errorMessage = VaultError(error).localizedMessage
        }
        await reload()
    }

    private func revoke(_ id: String?) async {
        do {
            try await model.session.revokeGrants(dataDirectory: dir, grantID: id)
        } catch {
            errorMessage = VaultError(error).localizedMessage
        }
        await reload()
    }

    private func pairProgram() {
        let panel = NSOpenPanel()
        panel.message = String(localized: "developer.chooseProgramToPair")
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task {
            guard await confirmed(String(localized: "developer.pairWithOnepass \(url.lastPathComponent)")) else { return }
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            do {
                let id = try await model.session.pairProgram(dataDirectory: dir, path: url.path)
                model.showToast(String(localized: "developer.programPaired \(id)"))
            } catch {
                errorMessage = VaultError(error).localizedMessage
            }
            await reload()
        }
    }

    private func chooseKnownHosts() {
        let panel = NSOpenPanel()
        panel.message = String(localized: "developer.chooseKnownHostsFile")
        panel.showsHiddenFiles = true
        panel.directoryURL = URL(fileURLWithPath: NSHomeDirectory()).appending(path: ".ssh")
        guard panel.runModal() == .OK, let url = panel.url,
            let bookmark = try? url.bookmarkData(options: [.withSecurityScope, .securityScopeAllowOnlyReadAccess])
        else { return }
        update { $0.knownHostsBookmark = bookmark }
    }
}

/// The first row of a card of this page: the tile of the redesign, a title and one line.
private struct CardHeading: View {
    let symbol: String
    let color: Color
    let title: String
    let message: String

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            PageTile(symbol: symbol, color: color, size: 30)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.headline)
                Text(message)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.vertical, 2)
    }
}

/// The scopes of one vault, as a menu of checkmarks. Empty: not exposed. `fill` is offered only when
/// asked (a client, on a vault whose policy has it); a `fill` already selected is kept either way,
/// the vault's own one being set by its toggle in the agent web fill section.
private struct ScopeMenu: View {
    let selected: [String]
    var offersFill = false
    let onChange: ([String]) -> Void

    static let all: [(String, LocalizedStringKey)] = [
        ("metadata", "Métadonnées"), ("use", "Utiliser"), ("write", "Créer"),
        ("totp", "Codes à usage unique"), ("reveal", "Révéler"), ("fill", "developer.webFillScope"),
    ]

    private var offered: [(String, LocalizedStringKey)] {
        offersFill ? Self.all : Self.all.filter { $0.0 != "fill" }
    }

    var body: some View {
        Menu {
            ForEach(offered, id: \.0) { scope, title in
                Toggle(isOn: Binding(
                    get: { selected.contains(scope) },
                    set: { on in
                        var next = Set(selected)
                        if on { next.insert(scope) } else { next.remove(scope) }
                        if on, scope != "metadata" { next.insert("metadata") }
                        if !on, scope == "metadata" { next.removeAll() }
                        onChange(Self.all.map(\.0).filter(next.contains))
                    })) { Text(title) }
            }
        } label: {
            Text(summary)
        }
        .fixedSize()
    }

    private var summary: String {
        if selected.isEmpty { return String(localized: "developer.notExposed") }
        if selected.contains("reveal") { return String(localized: "Révéler") }
        if selected.contains("use") { return String(localized: "Utiliser") }
        return String(localized: "Métadonnées")
    }
}
#endif

#if DEBUG && os(macOS)
/// Demo data and UI tests: stands for the bundled relay, never runs it (nothing is written to the
/// real home). Prints what the relay prints (Claude Code's format, a file that does not exist yet).
struct DemoHelperRunner: HelperRunner {
    func run(_ executable: URL, arguments: [String]) async -> HelperResult {
        func value(_ flag: String) -> String? {
            arguments.firstIndex(of: flag).flatMap { $0 + 1 < arguments.count ? arguments[$0 + 1] : nil }
        }
        let home = value("--home") ?? "/Users/camille"
        let socket = value("--socket") ?? home + "/Library/Containers/me.somalabs.onepass/Data/.onepass/mcp.sock"
        let file = home + "/.claude.json"
        if arguments.contains("--dry-run") {
            return HelperResult(status: 0, output: """
                --- \(file)
                +++ \(file)
                +{
                +  "mcpServers": {
                +    "onepass": {
                +      "type": "stdio",
                +      "command": "\(executable.path)",
                +      "args": [
                +        "--socket",
                +        "\(socket)"
                +      ]
                +    }
                +  }
                +}
                """)
        }
        return HelperResult(status: 0, output: """
            OnePass installed in \(file)
            Quit Claude Code first if it is running, then start it again: it can rewrite its configuration file and undo this change.
            """)
    }
}
#endif
