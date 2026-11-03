#if os(macOS)
import AppKit
import DesignKit
import SwiftUI
import UniformTypeIdentifiers
import VaultKit

/// "Nouvelle clé SSH": generate a key or import a private key file into an SSH Key item, with its
/// host bookmarks and agent settings. The private key never leaves the vault.
struct SSHKeySheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    private enum Source: Hashable { case generate, importFile }

    @State private var source: Source = .generate
    @State private var keyType: FfiSshKeyType = .ed25519
    @State private var title = ""
    @State private var vaultID = ""
    @State private var hosts = ""
    @State private var useInAgent = true
    @State private var confirmEachUse = false
    @State private var importedText: String?
    @State private var importedName = ""
    @State private var passphrase = ""
    @State private var needsPassphrase = false
    @State private var saving = false
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            Form {
                Picker("developer.source", selection: $source) {
                    Text("Générer").tag(Source.generate)
                    Text("developer.importFile").tag(Source.importFile)
                }
                .pickerStyle(.segmented)
                Section {
                    TextField("app.title", text: $title, prompt: Text("Github"))
                        .accessibilityIdentifier("sshKey.title")
                    Picker("term.vault", selection: $vaultID) {
                        ForEach(model.session.vaults, id: \.id) { Text($0.meta.name).tag($0.id) }
                    }
                    if source == .generate {
                        Picker("app.type", selection: $keyType) {
                            Text("developer.ed25519Recommended").tag(FfiSshKeyType.ed25519)
                            Text("developer.ecdsaP256").tag(FfiSshKeyType.ecdsaP256)
                            Text("developer.ecdsaP384").tag(FfiSshKeyType.ecdsaP384)
                            Text("developer.ecdsaP521").tag(FfiSshKeyType.ecdsaP521)
                            Text("developer.rsa3072").tag(FfiSshKeyType.rsa3072)
                            Text("developer.rsa4096").tag(FfiSshKeyType.rsa4096)
                        }
                    } else {
                        LabeledContent("app.file") {
                            HStack {
                                Text(importedText == nil ? String(localized: "app.none") : importedName)
                                    .foregroundStyle(.secondary)
                                Button("Choisir…") { chooseFile() }
                            }
                        }
                        if needsPassphrase {
                            SecureField("developer.keyPassphrase", text: $passphrase)
                        }
                    }
                }
                Section {
                    TextField("developer.hosts", text: $hosts, prompt: Text("github.com, *.exemple.fr"))
                    Toggle("developer.useInSshAgent", isOn: $useInAgent)
                    Toggle("developer.askAtEveryUse", isOn: $confirmEachUse)
                } footer: {
                    Text("developer.keyBoundToHosts")
                }
                if let errorMessage {
                    Section { Text(errorMessage).foregroundStyle(.orange) }
                }
            }
            .formStyle(.grouped)
            .navigationTitle("developer.newSshKey")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Annuler") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(source == .generate ? "Générer" : "Importer") { save() }
                        .disabled(!canSave)
                        .accessibilityIdentifier("sshKey.save")
                }
            }
        }
        .frame(width: 520, height: 520)
        .onAppear {
            if vaultID.isEmpty { vaultID = model.session.vaults.first?.id ?? "" }
        }
    }

    private var canSave: Bool {
        !saving && !title.trimmingCharacters(in: .whitespaces).isEmpty && !vaultID.isEmpty
            && (source == .generate || importedText != nil)
    }

    private var newKey: FfiNewSshKey {
        FfiNewSshKey(
            vaultId: vaultID, title: title.trimmingCharacters(in: .whitespaces),
            hosts: hosts.split(whereSeparator: { $0 == "," || $0 == " " }).map(String.init),
            useInAgent: useInAgent, confirmEachUse: confirmEachUse, comment: nil)
    }

    private func chooseFile() {
        let panel = NSOpenPanel()
        panel.message = String(localized: "developer.chooseSshPrivateKey")
        panel.showsHiddenFiles = true
        panel.directoryURL = URL(fileURLWithPath: NSHomeDirectory()).appending(path: ".ssh")
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        guard let data = try? Data(contentsOf: url), data.count < 64 << 10,
            let text = String(data: data, encoding: .utf8)
        else {
            errorMessage = String(localized: "developer.fileNotReadableSsh")
            return
        }
        importedText = text
        importedName = url.lastPathComponent
        needsPassphrase = sshKeyIsEncrypted(privateKey: text)
        if title.isEmpty { title = url.deletingPathExtension().lastPathComponent }
        errorMessage = nil
    }

    private func save() {
        saving = true
        errorMessage = nil
        let new = newKey
        Task {
            defer { saving = false }
            do {
                if source == .generate {
                    try await model.session.generateSSHKey(type: keyType, new)
                } else if let text = importedText {
                    try await model.session.importSSHKey(
                        privateKey: text, passphrase: needsPassphrase ? passphrase : nil, new)
                }
                importedText = nil
                passphrase = ""
                model.showToast(String(localized: "developer.sshKeyCreated"))
                dismiss()
            } catch {
                errorMessage = VaultError(error).localizedMessage
            }
        }
    }
}
#endif
