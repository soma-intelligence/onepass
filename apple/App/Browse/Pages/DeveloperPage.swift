import DesignKit
import SwiftUI
import VaultKit

/// Développeur page: the tools of milestone 7 (SSH agent, MCP server) and the CLI. On the Mac the app
/// serves the agent and the MCP server on its own vaults: their cards open Réglages > Développeur.
/// Elsewhere they run from the `onepass` command line, with its own data folder, and the cards say how.
struct DeveloperPage: View {
    @Environment(AppModel.self) private var model
    #if os(macOS)
    @Environment(\.openSettings) private var openSettings
    #endif
    @State private var guide: DeveloperGuide?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                PageHeader(
                    title: String(localized: "Développeur"), symbol: "chevron.left.forwardslash.chevron.right",
                    color: Color(red: 0x47 / 255, green: 0x55 / 255, blue: 0x69 / 255),
                    message: String(localized: "Utilise tes secrets dans le terminal, avec Git et tes agents IA, sans les copier en clair."))
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 300), spacing: 14)], spacing: 14) {
                    DeveloperCard(
                        tile: AnyView(CategoryTile(category: .of(.sshKey), size: 34)),
                        title: String(localized: "Agent SSH"),
                        message: String(localized: "Garde tes clés SSH dans un coffre, connecte-toi à tes serveurs et signe tes commits Git, avec une approbation à chaque usage."),
                        button: String(localized: "Voir l'agent SSH")
                    ) { show(.ssh) }
                    DeveloperCard(
                        tile: AnyView(PageTile(symbol: "point.3.connected.trianglepath.dotted", color: .purple, size: 34)),
                        title: String(localized: "Serveur MCP"),
                        message: String(localized: "Laisse un agent IA utiliser les coffres que tu choisis, sans jamais lui montrer un secret."),
                        button: String(localized: "Voir le serveur MCP")
                    ) { show(.mcp) }
                    DeveloperCard(
                        tile: AnyView(PageTile(symbol: "terminal.fill", color: .black, size: 34)),
                        title: String(localized: "CLI"),
                        message: String(localized: "Gère tes coffres depuis le terminal : recherche, génération, import, Watchtower et sauvegardes."),
                        button: String(localized: "Voir la CLI")
                    ) { guide = .cli }
                    DeveloperCard(
                        tile: AnyView(PageTile(symbol: "checkmark.shield.fill", color: Theme.accent, size: 34)),
                        title: String(localized: "Secrets sur le disque"),
                        message: String(localized: "Repère les mots de passe faibles, réutilisés ou compromis rangés dans tes coffres."),
                        button: String(localized: "Voir Watchtower")
                    ) { model.page = .watchtower }
                }
            }
            .padding(28)
            .frame(maxWidth: 1100, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        .navigationTitle(String(localized: "Développeur"))
        .sheet(item: $guide) { guide in
            DeveloperGuideSheet(guide: guide)
        }
        .accessibilityIdentifier("page.developer")
    }

    /// The Mac app serves the agent and the MCP server: their settings. Elsewhere, the CLI guide.
    private func show(_ g: DeveloperGuide) {
        #if os(macOS)
        model.settingsPageRequest = .developer
        openSettings()
        #else
        guide = g
        #endif
    }
}

private struct DeveloperCard: View {
    let tile: AnyView
    let title: String
    let message: String
    let button: String
    let action: () -> Void

    var body: some View {
        EditorCard {
            VStack(alignment: .leading, spacing: 12) {
                tile
                Text(title).font(.title3.weight(.semibold))
                Text(message)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 0)
                PageLinkButton(title: button, action: action)
            }
            .padding(18)
            .frame(maxWidth: .infinity, minHeight: 220, alignment: .topLeading)
        }
    }
}

// MARK: - Guides

enum DeveloperGuide: String, Identifiable {
    case ssh, mcp, cli
    var id: String { rawValue }
}

/// How to start a milestone 7 tool from the CLI, with commands to copy.
struct DeveloperGuideSheet: View {
    let guide: DeveloperGuide
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    content
                    devModeNote
                }
                .padding(24)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .navigationTitle(title)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("OK") { dismiss() }
                }
            }
        }
        #if os(macOS)
        .frame(width: 600, height: 620)
        #endif
    }

    private var title: String {
        switch guide {
        case .ssh: String(localized: "Agent SSH")
        case .mcp: String(localized: "Serveur MCP")
        case .cli: String(localized: "CLI")
        }
    }

    @ViewBuilder private var content: some View {
        switch guide {
        case .ssh: ssh
        case .mcp: mcp
        case .cli: cli
        }
    }

    private func copy(_ code: String) {
        model.session.copy(code, concealed: false)
        model.showToast(String(localized: "Commande copiée"))
    }

    private func step(_ text: String, _ code: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(text).font(.callout).fixedSize(horizontal: false, vertical: true)
            CodeBox(code: code, onCopy: copy)
        }
    }

    @ViewBuilder private var ssh: some View {
        Text("L'agent de la CLI sert les clés SSH de ses coffres à `ssh` et à `git`. Chaque signature demande ton accord dans le terminal, avec le titre de la clé, son empreinte et le programme qui la demande. La clé privée ne quitte jamais le coffre.")
            .fixedSize(horizontal: false, vertical: true)
        step(String(localized: "Crée une clé et rends-la disponible pour l'agent :"),
             #"onepass ssh-key generate --title "Github" --type ed25519 --host github.com --agent"#)
        step(String(localized: "Lance l'agent, puis indique son socket à ton terminal :"),
             "onepass ssh-agent\nexport SSH_AUTH_SOCK=~/.onepass-dev/ssh-agent.sock")
        step(String(localized: "Pour signer tes commits Git avec cette clé :"),
             "git config --global gpg.format ssh\ngit config --global user.signingkey \"$(onepass ssh-key public Github)\"\ngit config --global commit.gpgsign true")
        step(String(localized: "Écris une configuration SSH pour tes serveurs (OnePass ne modifie jamais ~/.ssh/config, tu ajoutes toi-même la ligne Include affichée) :"),
             "onepass ssh-key config --out ~/.onepass-ssh")
        Button {
            dismiss()
            model.showItems(.category(.sshKey))
        } label: {
            Label("Voir mes clés SSH", systemImage: "key.fill")
        }
    }

    @ViewBuilder private var mcp: some View {
        Text("Le serveur MCP de la CLI parle JSON-RPC sur l'entrée et la sortie standard. Il ne voit que les coffres créés avec l'accès MCP, et chaque usage d'un secret demande ton accord dans le terminal. L'agent reçoit des métadonnées ou le résultat d'une commande masquée, jamais la valeur.")
            .fixedSize(horizontal: false, vertical: true)
        step(String(localized: "Crée un coffre réservé aux agents et ranges-y leurs secrets :"),
             #"onepass vault create "Agents" --mcp-access"#)
        step(String(localized: "Choisis ce que les agents peuvent faire dans ce coffre :"),
             "onepass mcp policy set --vault Agents --scopes metadata,use")
        step(String(localized: "Déclare le serveur dans ton client MCP (OnePass ne l'inscrit jamais pour toi) :"),
             """
             {
               "mcpServers": {
                 "onepass": {
                   "command": "/chemin/vers/onepass",
                   "args": ["mcp", "--vault", "Agents"]
                 }
               }
             }
             """)
        Text("La politique signée décide des droits du client, `reveal_secret` et `totp_code` demandent Touch ID, et `onepass mcp audit` affiche le journal de chaque accès. Le mot de passe maître est demandé dans le terminal. Sur Mac, l'app sert un serveur MCP sans terminal, avec appairage des clients : Réglages > Développeur.")
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }

    @ViewBuilder private var cli: some View {
        Text("La commande `onepass` se compile depuis le dépôt, avec Rust.")
            .fixedSize(horizontal: false, vertical: true)
        step(String(localized: "Installe-la :"),
             "cargo install --locked --path core/onepass-cli")
        step(String(localized: "Quelques commandes :"),
             """
             onepass account create
             onepass item list
             onepass generate --length 24
             onepass watchtower
             onepass import export.csv --vault Personnel
             """)
        step(String(localized: "Toutes les commandes et leurs options :"), "onepass --help")
    }

    private var devModeNote: some View {
        Label {
            Text("La CLI utilise son propre dossier de données (`~/.onepass-dev`), pas les coffres de cette app. Sur Mac, l'app sert elle-même l'agent SSH et le serveur MCP sur tes coffres : Réglages > Développeur.")
                .fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: "info.circle")
        }
        .font(.callout)
        .foregroundStyle(.secondary)
        .padding(.top, 6)
    }
}
