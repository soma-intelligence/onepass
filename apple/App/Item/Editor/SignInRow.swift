import DesignKit
import SwiftUI
import VaultKit

/// "se connecter avec" in a login's main card: the provider and the account item it uses, a menu
/// to pick another account, and a (−) that drops the provider. The username row stays as typed.
struct SignInRow: View {
    @Bindable var editor: ItemEditorModel
    @State private var choosing: LoginProvider?

    var body: some View {
        if let current = editor.draft.item.signInProvider {
            HStack(spacing: Theme.Space.m) {
                Menu {
                    Button("item.changeAccount", systemImage: "arrow.triangle.2.circlepath") {
                        choosing = LoginProvider(rawValue: current.provider)
                    }
                    .accessibilityIdentifier("editor.signIn.account")
                } label: {
                    HStack(spacing: Theme.Space.m) {
                        VStack(alignment: .leading, spacing: Theme.Space.xs) {
                            EditorLabel(String(localized: "editor.signInWith"))
                            SignInAccountLine(provider: current.provider, accountItemID: current.accountItemID)
                        }
                        Spacer(minLength: 8)
                        Image(systemName: "chevron.up.chevron.down")
                            .font(.footnote.weight(.semibold))
                            .foregroundStyle(.tertiary)
                    }
                    .contentShape(.rect)
                }
                .menuStyle(.button)
                .buttonStyle(.plain)
                .menuIndicator(.hidden)
                .accessibilityIdentifier("editor.signIn.current")
                RemoveRowButton { editor.clearSignInProvider() }
                    .accessibilityLabel(Text("editor.signIn.remove"))
                    .accessibilityIdentifier("editor.signIn.remove")
            }
            .editorRowPadding()
            .sheet(item: $choosing) { provider in
                SignInAccountChooser(provider: provider, ownID: editor.draft.item.id) { accountID in
                    editor.draft.item.setSignInProvider(provider.rawValue, accountItemID: accountID)
                    choosing = nil
                }
            }
        }
    }
}
