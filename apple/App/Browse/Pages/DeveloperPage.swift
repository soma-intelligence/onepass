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
                    message: String(localized: "browse.useSecretsInTerminal"))
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 300), spacing: 14)], spacing: 14) {
                    DeveloperCard(
                        tile: AnyView(CategoryTile(category: .of(.sshKey), size: 34)),
                        title: String(localized: "app.sshAgent"),
                        message: String(localized: "browse.keepSshKeysIn"),
                        button: String(localized: "browse.viewSshAgent")
                    ) { show(.ssh) }
                    DeveloperCard(
                        tile: AnyView(PageTile(symbol: "point.3.connected.trianglepath.dotted", color: .purple, size: 34)),
                        title: String(localized: "app.mcpServer"),
                        message: String(localized: "browse.letAiAgentUse"),
                        button: String(localized: "browse.viewMcpServer")
                    ) { show(.mcp) }
                    DeveloperCard(
                        tile: AnyView(PageTile(symbol: "terminal.fill", color: .black, size: 34)),
                        title: String(localized: "browse.cli"),
                        message: String(localized: "browse.manageVaultsFromTerminal"),
                        button: String(localized: "browse.viewCli")
                    ) { guide = .cli }
                    DeveloperCard(
                        tile: AnyView(PageTile(symbol: "checkmark.shield.fill", color: Theme.accent, size: 34)),
                        title: String(localized: "browse.secretsOnDisk"),
                        message: String(localized: "browse.findsWeakReusedOr"),
                        button: String(localized: "browse.viewWatchtower")
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
        case .ssh: String(localized: "app.sshAgent")
        case .mcp: String(localized: "app.mcpServer")
        case .cli: String(localized: "browse.cli")
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
        model.showToast(String(localized: "browse.commandCopied"))
    }

    private func step(_ text: String, _ code: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(text).font(.callout).fixedSize(horizontal: false, vertical: true)
            CodeBox(code: code, onCopy: copy)
        }
    }

    @ViewBuilder private var ssh: some View {
        Text("browse.cliAgentServesSsh")
            .fixedSize(horizontal: false, vertical: true)
        step(String(localized: "browse.createKeyAndMake"),
             #"onepass ssh-key generate --title "Github" --type ed25519 --host github.com --agent"#)
        step(String(localized: "browse.startAgentThenPoint"),
             "onepass ssh-agent\nexport SSH_AUTH_SOCK=~/.onepass-dev/ssh-agent.sock")
        step(String(localized: "browse.toSignGitCommits"),
             "git config --global gpg.format ssh\ngit config --global user.signingkey \"$(onepass ssh-key public Github)\"\ngit config --global commit.gpgsign true")
        step(String(localized: "browse.writeSshConfigurationFor"),
             "onepass ssh-key config --out ~/.onepass-ssh")
        Button {
            dismiss()
            model.showItems(.category(.sshKey))
        } label: {
            Label("browse.viewMySshKeys", systemImage: "key.fill")
        }
    }

    @ViewBuilder private var mcp: some View {
        Text("browse.cliMcpServerSpeaks")
            .fixedSize(horizontal: false, vertical: true)
        step(String(localized: "browse.createVaultForAgents"),
             #"onepass vault create "Agents" --mcp-access"#)
        step(String(localized: "browse.chooseWhatAgentsCan"),
             "onepass mcp policy set --vault Agents --scopes metadata,use")
        step(String(localized: "browse.addServerToMcp"),
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
        Text("browse.signedPolicyDecidesWhat")
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }

    @ViewBuilder private var cli: some View {
        Text("browse.onepassCommandBuiltFrom")
            .fixedSize(horizontal: false, vertical: true)
        step(String(localized: "browse.installIt"),
             "cargo install --locked --path core/onepass-cli")
        step(String(localized: "browse.fewCommands"),
             """
             onepass account create
             onepass item list
             onepass generate --length 24
             onepass watchtower
             onepass import export.csv --vault Personnel
             """)
        step(String(localized: "browse.allCommandsAndTheir"), "onepass --help")
    }

    private var devModeNote: some View {
        Label {
            Text("browse.cliUsesOwnData")
                .fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: "info.circle")
        }
        .font(.callout)
        .foregroundStyle(.secondary)
        .padding(.top, 6)
    }
}
