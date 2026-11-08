import DesignKit
import SwiftUI
import VaultKit

/// The accounts of one verification code link (`AppModel.otpLinkRequest`). Holds the secrets until
/// the sheet closes or the app locks.
struct OtpLinkRequest: Identifiable {
    /// A link opened by the system (another app, a site) or a QR code scanned in the app.
    enum Source {
        case link, scan
    }

    let id = UUID()
    let accounts: [OtpLinkAccount]
    let source: Source
}

/// "Ajouter un code": a verification code link opened by the system (OnePass chosen in Réglages >
/// Codes de vérification), or a QR code scanned in the app. One account goes straight to its page;
/// a Google Authenticator export lists its accounts, one Login each. Each code goes into an
/// existing Login (search, the likely ones first) or a new one, with the live code shown.
struct AddOtpSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let request: OtpLinkRequest
    /// Accounts already added, with the title of the Login that took them.
    @State private var added: [Int: String] = [:]

    var body: some View {
        NavigationStack {
            Group {
                if request.accounts.count == 1, let account = request.accounts.first {
                    OtpAccountTarget(account: account, source: request.source) { title in
                        model.showToast(String(localized: "item.codeAddedTo \(title)"))
                        dismiss()
                    }
                } else {
                    list
                }
            }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button {
                        dismiss()
                    } label: {
                        added.isEmpty ? Text("Annuler") : Text("common.done")
                    }
                    .accessibilityIdentifier("addOtp.close")
                }
            }
        }
        #if os(macOS)
        .frame(minWidth: 420, minHeight: 480)
        #endif
    }

    private var list: some View {
        List {
            Section {
                ForEach(request.accounts) { account in
                    NavigationLink {
                        OtpAccountTarget(account: account, source: request.source) { title in
                            added[account.id] = title
                        }
                    } label: {
                        HStack(spacing: Theme.Space.m) {
                            VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                                Text(account.title)
                                if let name = account.account, name != account.title {
                                    Text(name).font(.footnote).foregroundStyle(.secondary)
                                }
                            }
                            Spacer()
                            if let title = added[account.id] {
                                Label(title, systemImage: "checkmark.circle.fill")
                                    .labelStyle(.iconOnly)
                                    .foregroundStyle(.green)
                                    .accessibilityLabel(Text("item.addedTo \(title)"))
                            }
                        }
                    }
                    .disabled(added[account.id] != nil)
                    .accessibilityIdentifier("addOtp.account.\(account.id)")
                }
            } footer: {
                VStack(alignment: .leading, spacing: Theme.Space.xs) {
                    if request.source == .link { Text("item.linkComesFromAnother") }
                    Text("item.codesInExportEach \(request.accounts.count)")
                }
            }
        }
        .navigationTitle("item.addCodes")
        #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
    }
}

/// One account: its live code, "Nouvel élément Login", then the Logins to attach it to. A
/// `reprompt` Login asks for biometrics or the master password before anything about it is read
/// or written, like its item page.
private struct OtpAccountTarget: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let account: OtpLinkAccount
    let source: OtpLinkRequest.Source
    /// Called with the Login's title once the code is stored.
    let onAdded: (String) -> Void
    @State private var query = ""
    @State private var busy = false
    @State private var replacing: FfiItemSummary?
    /// A `reprompt` Login waiting for the master password (no biometrics on this device).
    @State private var passwordFor: FfiItemSummary?
    /// `reprompt` Logins the user confirmed in this sheet.
    @State private var confirmedIDs: Set<String> = []

    private var logins: [FfiItemSummary] { model.session.otpCandidateLogins(query: query) }

    private var suggested: [FfiItemSummary] {
        query.isEmpty ? Array(account.suggestions(in: logins).prefix(3)) : []
    }

    private var others: [FfiItemSummary] {
        let shown = Set(suggested.map(\.id))
        return logins.filter { !shown.contains($0.id) }
    }

    var body: some View {
        List {
            Section {
                LabeledContent {
                    TotpCodeView(secret: account.uri, compact: true)
                        .privacySensitive()
                } label: {
                    VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                        Text(account.title)
                        if let name = account.account, name != account.title {
                            Text(name).font(.footnote).foregroundStyle(.secondary)
                        }
                    }
                }
            } footer: {
                if source == .link { Text("item.linkComesFromAnother") }
            }
            Section {
                Button {
                    Task { await create() }
                } label: {
                    Label("item.newLoginItem", systemImage: "plus.circle")
                }
                .disabled(busy || model.vaultForNewItem == nil)
                .accessibilityIdentifier("addOtp.newLogin")
            } footer: {
                Text("item.titleInVault \(account.title) \(vaultName)")
            }
            if !suggested.isEmpty {
                Section("item.suggestions") {
                    ForEach(suggested, id: \.id) { row($0) }
                }
            }
            Section {
                if others.isEmpty {
                    (query.isEmpty ? Text("item.noLoginItems") : Text("item.noResults"))
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(others, id: \.id) { row($0) }
                }
            } header: {
                query.isEmpty ? Text("item.addToExistingItem") : Text("item.results")
            }
        }
        .searchable(text: $query, prompt: Text("item.searchForLoginItem"))
        .navigationTitle("item.addCode")
        #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
        .alert(
            Text("item.replaceExistingCode"),
            isPresented: Binding(get: { replacing != nil }, set: { if !$0 { replacing = nil } }),
            presenting: replacing
        ) { login in
            Button("app.replace", role: .destructive) { Task { await attach(login) } }
            Button("Annuler", role: .cancel) { replacing = nil }
        } message: { login in
            Text("item.alreadyHasOneTime \(login.title)")
        }
        .sheet(isPresented: Binding(get: { passwordFor != nil }, set: { if !$0 { passwordFor = nil } })) {
            if let login = passwordFor {
                PasswordPromptSheet(
                    title: "Confirmer ton identité",
                    footer: "item.itemAsksForConfirmation"
                ) { password in
                    try await model.session.verifyMasterPassword(password)
                    confirmedIDs.insert(login.id)
                    // Once the prompt is gone, so the replace question can appear.
                    Task {
                        try? await Task.sleep(for: .milliseconds(600))
                        await pick(login)
                    }
                }
            }
        }
    }

    private var vaultName: String {
        guard let id = model.vaultForNewItem else { return "" }
        return model.session.vaults.first { $0.id == id }?.meta.name ?? ""
    }

    private func row(_ login: FfiItemSummary) -> some View {
        Button {
            Task { await pick(login) }
        } label: {
            HStack(spacing: Theme.Space.m) {
                ItemIcon(type: login.itemType, title: login.title, siteIcon: model.iconLoader.cachedIcon(for: login.primaryUrl, title: login.title), size: 30)
                VStack(alignment: .leading) {
                    Text(login.title).foregroundStyle(.primary)
                    if !login.subtitle.isEmpty {
                        Text(login.subtitle).font(.footnote).foregroundStyle(.secondary)
                    }
                }
            }
        }
        .disabled(busy)
        .accessibilityIdentifier("addOtp.login.\(login.id)")
    }

    private func pick(_ login: FfiItemSummary) async {
        busy = true
        defer { busy = false }
        do {
            var target = try await model.session.otpTarget(
                itemID: login.id, vaultID: login.vaultId, confirmed: confirmedIDs.contains(login.id))
            if target == .confirmFirst {
                guard await model.session.confirmUserPresence(prompt: String(localized: "item.edit \(login.title)"))
                else {
                    passwordFor = login
                    return
                }
                confirmedIDs.insert(login.id)
                target = try await model.session.otpTarget(itemID: login.id, vaultID: login.vaultId, confirmed: true)
            }
            if target == .ready(hasOtp: true) {
                replacing = login
            } else {
                await attach(login)
            }
        } catch {
            model.showToast(VaultError(error).localizedMessage, kind: .error)
        }
    }

    private func attach(_ login: FfiItemSummary) async {
        replacing = nil
        busy = true
        defer { busy = false }
        do {
            let item = try await model.session.attachOtp(
                account, toItemID: login.id, vaultID: login.vaultId, confirmed: confirmedIDs.contains(login.id))
            done(item.title)
        } catch {
            model.showToast(VaultError(error).localizedMessage, kind: .error)
        }
    }

    private func create() async {
        guard let vaultID = model.vaultForNewItem else { return }
        busy = true
        defer { busy = false }
        do {
            let item = try await model.session.createLogin(with: account, vaultID: vaultID)
            done(item.title)
        } catch {
            model.showToast(VaultError(error).localizedMessage, kind: .error)
        }
    }

    /// Back to the account list, or the sheet closes (one account).
    private func done(_ title: String) {
        onAdded(title)
        dismiss()
    }
}
