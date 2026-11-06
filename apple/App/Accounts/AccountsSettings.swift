import DesignKit
import SwiftUI
import VaultKit

/// Réglages > Comptes (multi-account spec 7): the accounts of this device, each with its name, color
/// and work domains; the unified search choice; adding and removing an account.
struct AccountsSettings: View {
    @Environment(AppModel.self) private var model
    /// "Ajouter un compte" opens here, over Réglages: the root's sheet (`showAddAccount`) cannot
    /// show while Réglages, itself a sheet, is up.
    @State private var adding = false

    var body: some View {
        Form {
            Section {
                ForEach(model.accounts.profiles) { profile in
                    NavigationLink {
                        AccountDetailSettings(slot: profile.slot)
                    } label: {
                        AccountRowLabel(profile: profile, avatarSize: 32)
                    }
                    .accessibilityIdentifier("settings.accounts.\(profile.isPrimary ? "primary" : profile.slot)")
                }
                .onMove { from, to in
                    guard let index = from.first else { return }
                    let slot = model.accounts.profiles[index].slot
                    do throws(AccountsError) {
                        try model.accounts.move(slot, to: to > index ? to - 1 : to)
                    } catch {
                        model.showToast(error.message, kind: .error)
                    }
                }
                Button {
                    adding = true
                } label: {
                    Label("accounts.add", systemImage: "plus")
                }
                .accessibilityIdentifier("settings.accounts.add")
            } footer: {
                Text("accounts.settings.footer")
            }
            if model.accounts.hasSeveralAccounts {
                Section {
                    Toggle("accounts.settings.unifiedSearch", isOn: Binding(
                        get: { model.accounts.unifiedSearch },
                        set: { enabled in
                            do throws(AccountsError) {
                                try model.accounts.setUnifiedSearch(enabled)
                            } catch {
                                model.showToast(error.message, kind: .error)
                            }
                        }
                    ))
                    .accessibilityIdentifier("settings.accounts.unifiedSearch")
                } footer: {
                    Text("accounts.settings.unifiedSearch.footer")
                }
            }
        }
        .settingsPage("accounts.title")
        .sheet(isPresented: $adding) {
            AddAccountSheet()
        }
    }
}

/// One account: its name, color and the work domains AutoFill sends to it. An added account can be
/// taken off this device; the primary account cannot (ruling P3).
struct AccountDetailSettings: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let slot: String
    @State private var label = ""
    @State private var color: FfiAccountColor = .blue
    @State private var domains: [String] = []
    @State private var newDomain = ""
    @State private var confirmingRemoval = false
    @State private var loaded = false

    var body: some View {
        Form {
            if let profile = model.accounts.profile(slot) {
                Section {
                    TextField("accounts.detail.name", text: $label, prompt: Text(verbatim: model.displayName(of: profile)))
                        .onSubmit { save() }
                        .accessibilityIdentifier("settings.accounts.detail.name")
                    LabeledContent("accounts.detail.kind") {
                        Text(verbatim: AccountStyle.kindName(profile.kind))
                    }
                } header: {
                    Text("accounts.detail.identity")
                }
                Section {
                    AccountColorPicker(color: $color)
                        .onChange(of: color) { save() }
                } header: {
                    Text("accounts.detail.color")
                }
                if !profile.isPrimary {
                    Section {
                        ForEach(domains, id: \.self) { domain in
                            Text(verbatim: domain)
                        }
                        .onDelete { offsets in
                            domains.remove(atOffsets: offsets)
                            save()
                        }
                        HStack {
                            TextField("accounts.detail.domains.placeholder", text: $newDomain)
                                #if os(iOS) || os(visionOS)
                                .textInputAutocapitalization(.never)
                                .keyboardType(.URL)
                                #endif
                                .autocorrectionDisabled()
                                .onSubmit(addDomain)
                                .accessibilityIdentifier("settings.accounts.detail.domain")
                            Button("common.add", action: addDomain)
                                .disabled(newDomain.trimmingCharacters(in: .whitespaces).isEmpty)
                        }
                    } header: {
                        Text("accounts.detail.domains")
                    } footer: {
                        Text("accounts.detail.domains.footer")
                    }
                    Section {
                        Button("accounts.detail.remove", role: .destructive) { confirmingRemoval = true }
                            .accessibilityIdentifier("settings.accounts.detail.remove")
                    } footer: {
                        Text("accounts.detail.remove.footer")
                    }
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle(Text(verbatim: model.accounts.profile(slot).map(model.displayName(of:)) ?? ""))
        #if os(iOS) || os(visionOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
        .onAppear(perform: load)
        .onDisappear { save() }
        .confirmationDialog("accounts.detail.remove.title", isPresented: $confirmingRemoval, titleVisibility: .visible) {
            Button("accounts.detail.remove.confirm", role: .destructive) {
                dismiss()
                model.removeAccount(slot)
            }
            Button("common.cancel", role: .cancel) {}
        } message: {
            Text("accounts.detail.remove.message")
        }
    }

    private func load() {
        guard !loaded, let profile = model.accounts.profile(slot) else { return }
        label = profile.label
        color = profile.color
        domains = profile.workDomains
        loaded = true
    }

    private func addDomain() {
        let domain = newDomain.trimmingCharacters(in: .whitespaces).lowercased()
        guard !domain.isEmpty, !domains.contains(domain) else { return }
        domains.append(domain)
        newDomain = ""
        if !save() { domains.removeLast() }
    }

    /// Writes the account through the core, which normalizes and checks the domains (each is claimed by
    /// one account only). Returns false when the core refused.
    @discardableResult
    private func save() -> Bool {
        guard loaded, let profile = model.accounts.profile(slot) else { return false }
        let trimmed = label.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed != profile.label || color != profile.color || domains != profile.workDomains else { return true }
        do {
            try model.accounts.update(slot, label: trimmed, color: color, workDomains: domains)
            domains = model.accounts.profile(slot)?.workDomains ?? domains
            return true
        } catch {
            model.showToast(error.message, kind: .error)
            return false
        }
    }
}

/// The eight account colors as a row of swatches.
struct AccountColorPicker: View {
    @Binding var color: FfiAccountColor

    var body: some View {
        HStack(spacing: 0) {
            ForEach(AccountStyle.palette, id: \.self) { option in
                Button {
                    color = option
                } label: {
                    Circle()
                        .fill(AccountStyle.color(option).gradient)
                        .frame(width: 28, height: 28)
                        .overlay {
                            if option == color {
                                Circle().strokeBorder(.background, lineWidth: 2.5).padding(2.5)
                            }
                        }
                        .frame(maxWidth: .infinity, minHeight: 36)
                        .contentShape(.rect)
                }
                .buttonStyle(.plain)
                .accessibilityLabel(Text(AccountStyle.colorName(option)))
                .accessibilityAddTraits(option == color ? .isSelected : [])
                .accessibilityIdentifier("accounts.color.\(option)")
            }
        }
    }
}
