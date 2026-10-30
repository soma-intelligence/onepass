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
                clientsSection
                grantsSection
            }
            phoneSection
            installSection
            Section {
                NavigationLink {
                    AuditLogView()
                } label: {
                    Label("Journal d'audit", systemImage: "list.bullet.rectangle")
                }
                .accessibilityIdentifier("settings.developer.audit")
            } footer: {
                Text("Chaque signature SSH et chaque accès MCP y sont inscrits, acceptés ou refusés. Le journal est chaîné et signé par ton compte : une ligne modifiée ou retirée se voit.")
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
                    Text("Agent SSH")
                    statusLine(running: hosts.sshRunning, error: hosts.sshError, enabled: hosts.settings.sshEnabled)
                }
            }
            .accessibilityIdentifier("settings.developer.ssh")
            if hosts.settings.sshEnabled {
                Toggle("Touch ID à chaque signature", isOn: setting(\.sshRequirePresence))
                    .accessibilityIdentifier("settings.developer.sshPresence")
                Toggle("Autoriser les connexions transférées", isOn: setting(\.sshAllowForwarded))
                LabeledContent("known_hosts") {
                    HStack {
                        Text(hosts.settings.knownHostsBookmark == nil ? "Non choisi" : "Choisi")
                            .foregroundStyle(.secondary)
                        Button(hosts.settings.knownHostsBookmark == nil ? "Choisir…" : "Changer…") { chooseKnownHosts() }
                        if hosts.settings.knownHostsBookmark != nil {
                            Button("Retirer") { update { $0.knownHostsBookmark = nil } }
                        }
                    }
                }
                VStack(alignment: .leading, spacing: 8) {
                    Text("Dans `~/.ssh/config` :").font(.callout)
                    CodeBox(code: "Host *\n  \(hosts.paths.identityAgentLine)", onCopy: copy)
                    Text("Ou dans ton terminal :").font(.callout)
                    CodeBox(code: hosts.paths.exportLine, onCopy: copy)
                }
                .padding(.vertical, 4)
            }
        } header: {
            Text("Agent SSH")
        } footer: {
            Text("L'app sert les clés SSH de tes coffres à `ssh` et à `git`. Chaque signature te demande ton accord, avec la clé, le programme et la destination. La clé privée ne quitte jamais OnePass. L'agent s'arrête quand l'app se verrouille.")
        }
    }

    @ViewBuilder private var sshKeysSection: some View {
        Section {
            if keys.isEmpty {
                Text("Aucune clé n'est proposée à l'agent. Active « Utiliser dans l'agent » sur une clé SSH, ou crée-en une.")
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
                    .help(Text("Copier la clé publique"))
                    .accessibilityLabel(Text("Copier la clé publique de \(key.title)"))
                }
            }
            Button {
                newKey = true
            } label: {
                Label("Nouvelle clé SSH…", systemImage: "plus")
            }
            .accessibilityIdentifier("settings.developer.newKey")
        } header: {
            Text("Clés proposées")
        }
    }

    // MARK: - MCP

    @ViewBuilder private var mcpSection: some View {
        Section {
            Toggle(isOn: setting(\.mcpEnabled)) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Serveur MCP")
                    statusLine(running: hosts.mcpRunning, error: hosts.mcpError, enabled: hosts.settings.mcpEnabled)
                }
            }
            .accessibilityIdentifier("settings.developer.mcp")
            if hosts.settings.mcpEnabled {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Pour déclarer OnePass à la main dans ton client MCP (ou utilise « Installer dans un agent » plus bas) :")
                        .font(.callout)
                    CodeBox(code: hosts.paths.mcpClientConfig, onCopy: copy)
                }
                .padding(.vertical, 4)
            }
        } header: {
            Text("Serveur MCP")
        } footer: {
            Text("Un agent IA appairé voit les coffres que tu exposes, utilise leurs secrets sans les voir, et chaque usage te demande ton accord. Révéler un secret ou un code demande Touch ID.")
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
                Toggle("Génération de mots de passe", isOn: Binding(
                    get: { policy.allowGenerate },
                    set: { allow in Task { await savePolicy(allowGenerate: allow) } }))
            }
        } header: {
            Text("Coffres exposés")
        } footer: {
            Text("Rien n'est exposé tant que tu ne le choisis pas ici. « Métadonnées » : titres et champs, jamais de valeur. « Utiliser » : lancer une commande avec les secrets, sortie masquée.")
        }
    }

    @ViewBuilder private var clientsSection: some View {
        Section {
            if clients.isEmpty {
                Text("Aucun client appairé. Un client signé demande l'appairage à sa première connexion.")
                    .foregroundStyle(.secondary)
            }
            ForEach(clients, id: \.id) { client in
                DisclosureGroup {
                    ForEach(policy?.vaults.filter(exposed) ?? [], id: \.vaultId) { vault in
                        HStack {
                            Text(vault.name)
                            Spacer()
                            ScopeMenu(selected: client.scopes.first { $0.vaultId == vault.vaultId }?.scopes ?? []) { scopes in
                                Task { await setClientScopes(client, vault: vault, scopes: scopes) }
                            }
                        }
                    }
                    Button("Désappairer", role: .destructive) { Task { await unpair(client) } }
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
                Label("Appairer un programme…", systemImage: "plus")
            }
        } header: {
            Text("Clients appairés")
        } footer: {
            Text("Un programme non signé par un développeur ne s'appaire qu'ici, en choisissant son fichier : il doit être réappairé après chaque mise à jour.")
        }
    }

    @ViewBuilder private var grantsSection: some View {
        Section {
            if grants.isEmpty {
                Text("Aucune autorisation en cours.").foregroundStyle(.secondary)
            }
            ForEach(grants, id: \.id) { grant in
                HStack {
                    VStack(alignment: .leading, spacing: 1) {
                        Text(grant.action)
                        Text("\(label(of: grant.clientId)) · jusqu'à \(Date(timeIntervalSince1970: TimeInterval(grant.expiresAt)).formatted(date: .omitted, time: .shortened))")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("Révoquer") { Task { await revoke(grant.id) } }
                }
            }
            if !grants.isEmpty {
                Button("Tout révoquer", role: .destructive) { Task { await revoke(nil) } }
            }
        } header: {
            Text("Autorisations en cours")
        }
    }

    // MARK: - iPhone

    @ViewBuilder private var phoneSection: some View {
        Section {
            CardHeading(
                symbol: "iphone", color: .blue, title: String(localized: "iPhone"),
                message: String(localized: "Approuve les demandes des agents sur ton iPhone, et déverrouille OnePass pour eux quand tu n'es pas devant ce Mac."))
            if !phones.available {
                Text("Cette version de OnePass n'utilise pas iCloud : les demandes s'approuvent sur ce Mac seulement.")
                    .foregroundStyle(.secondary)
            } else if phones.phones.isEmpty {
                Text("Aucun iPhone enrôlé. Sur ton iPhone, ouvre OnePass > Réglages > Agents et active les demandes des agents.")
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("settings.developer.noPhone")
            } else {
                ForEach(phones.phones) { phone in
                    Label {
                        VStack(alignment: .leading, spacing: 1) {
                            Text(phone.name)
                            Group {
                                if phone.id == phones.unlockPhone {
                                    Text("Approbations et déverrouillage")
                                } else {
                                    Text("Approbations")
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
                Toggle("Approuver aussi sur l'iPhone", isOn: Binding(
                    get: { phones.approveOnPhone },
                    set: { on in Task { await phones.setApproveOnPhone(on) } }))
                    .accessibilityIdentifier("settings.developer.phoneApprovals")
                if phones.phones.count > 1, phones.unlockPhone == nil {
                    Picker("iPhone qui déverrouille", selection: Binding(
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
                        Text("Déverrouiller depuis mon iPhone")
                        Text("Touch ID confirme. Ouvert depuis l'iPhone, OnePass sert seulement les agents : l'app reste verrouillée.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .disabled(phones.busy)
                .accessibilityIdentifier("settings.developer.phoneUnlock")
                if let code = phones.pairingCode {
                    Label("Sur ton iPhone, vérifie le code \(code) et accepte avec Face ID.", systemImage: "checkmark.shield")
                        .font(.callout)
                }
                Picker("Durée de la fenêtre des agents", selection: Binding(
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
            Text("Chaque demande part aussi vers ton iPhone, et la première réponse compte. La fenêtre des agents se ferme à son terme, quand ce Mac se met en veille ou quand tu verrouilles.")
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
                title: String(localized: "Installer dans un agent"),
                message: String(localized: "Ajoute OnePass à ton client MCP en un clic : seule son entrée « onepass » change, une sauvegarde est gardée."))
            Picker("Client", selection: $installer.client) {
                ForEach(AgentClient.allCases) { Text($0.title).tag($0) }
            }
            .accessibilityIdentifier("settings.developer.installClient")
            HStack {
                Button("Voir les changements") { Task { await installer.previewInstall() } }
                    .accessibilityIdentifier("settings.developer.installPreview")
                Button("Installer") { Task { await installer.install() } }
                    .disabled(!installer.canInstall)
                    .accessibilityIdentifier("settings.developer.install")
                if installer.running { ProgressView().controlSize(.small) }
            }
            .disabled(installer.running)
            if let result = installer.result {
                if result.succeeded {
                    Label("Installé. Quitte \(installer.client.title) puis relance-le.", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                } else {
                    Label("L'installation a échoué.", systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                }
                if !result.output.isEmpty { CodeBox(code: result.output, onCopy: copy) }
            } else if let preview = installer.preview {
                if preview.succeeded {
                    Text("Changements prévus :").font(.callout)
                } else {
                    Text("Aperçu impossible :").font(.callout)
                }
                CodeBox(code: preview.output.isEmpty ? String(localized: "Aucun changement.") : preview.output, onCopy: copy)
            }
            VStack(alignment: .leading, spacing: 8) {
                Text("Ou dans ton terminal :").font(.callout)
                CodeBox(code: installer.terminalCommand, onCopy: copy)
            }
            .padding(.vertical, 4)
        } footer: {
            Text("Quitte le client avant d'installer : il réécrit sa configuration en quittant. Le fichier d'origine est gardé à côté (.onepass-bak).")
        }
        .accessibilityIdentifier("settings.developer.installCard")
    }

    // MARK: - Pieces

    @ViewBuilder private func statusLine(running: Bool, error: String?, enabled: Bool) -> some View {
        if let error {
            Text(error).font(.caption).foregroundStyle(.orange)
        } else if running {
            Text("En marche").font(.caption).foregroundStyle(.green)
        } else if enabled {
            Text("Démarrage…").font(.caption).foregroundStyle(.secondary)
        } else {
            Text("Arrêté").font(.caption).foregroundStyle(.secondary)
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
        model.showToast(String(localized: "Copié"))
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
        if widening, !(await confirmed(String(localized: "Exposer « \(vault.name) » aux agents IA"))) { return }
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
            !(await confirmed(String(localized: "Donner plus de droits à \(client.label)")))
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
        panel.message = String(localized: "Choisis le programme à appairer avec le serveur MCP de OnePass.")
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task {
            guard await confirmed(String(localized: "Appairer \(url.lastPathComponent) avec OnePass")) else { return }
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            do {
                let id = try await model.session.pairProgram(dataDirectory: dir, path: url.path)
                model.showToast(String(localized: "Programme appairé : \(id)"))
            } catch {
                errorMessage = VaultError(error).localizedMessage
            }
            await reload()
        }
    }

    private func chooseKnownHosts() {
        let panel = NSOpenPanel()
        panel.message = String(localized: "Choisis ton fichier known_hosts (souvent ~/.ssh/known_hosts). OnePass le lit seulement.")
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

/// The scopes of one vault, as a menu of checkmarks. Empty: not exposed.
private struct ScopeMenu: View {
    let selected: [String]
    let onChange: ([String]) -> Void

    static let all: [(String, LocalizedStringKey)] = [
        ("metadata", "Métadonnées"), ("use", "Utiliser"), ("write", "Créer"),
        ("totp", "Codes à usage unique"), ("reveal", "Révéler"),
    ]

    var body: some View {
        Menu {
            ForEach(Self.all, id: \.0) { scope, title in
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
        if selected.isEmpty { return String(localized: "Non exposé") }
        if selected.contains("reveal") { return String(localized: "Révéler") }
        if selected.contains("use") { return String(localized: "Utiliser") }
        return String(localized: "Métadonnées")
    }
}
#endif

#if DEBUG && os(macOS)
/// Demo data and UI tests: stands for the bundled relay, never runs it (nothing is written to the
/// real home). Fictional output.
struct DemoHelperRunner: HelperRunner {
    func run(_ executable: URL, arguments: [String]) async -> HelperResult {
        let client = arguments.firstIndex(of: "--client").map { arguments[$0 + 1] } ?? "claude-code"
        if arguments.contains("--dry-run") {
            return HelperResult(status: 0, output: """
                --- ~/.claude.json
                +++ ~/.claude.json
                @@ mcpServers @@
                +    "onepass": {
                +      "command": "/Applications/OnePass.app/Contents/Helpers/onepass-mcp",
                +      "args": ["--socket", "~/Library/Containers/me.somalabs.onepass/Data/.onepass/mcp.sock"]
                +    }
                """)
        }
        return HelperResult(status: 0, output: "OnePass added to \(client). Quit the client first, then open it again.")
    }
}
#endif
