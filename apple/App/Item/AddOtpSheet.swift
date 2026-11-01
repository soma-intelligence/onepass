import DesignKit
import SwiftUI
import VaultKit

/// The accounts of one verification code link (`AppModel.otpLinkRequest`). Holds the secrets until
/// the sheet closes or the app locks.
struct OtpLinkRequest: Identifiable {
    let id = UUID()
    let accounts: [OtpLinkAccount]
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
                    OtpAccountTarget(account: account) { title in
                        model.showToast(String(localized: "Code ajouté à \(title)"))
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
                        added.isEmpty ? Text("Annuler") : Text("Terminé")
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
                        OtpAccountTarget(account: account) { title in
                            added[account.id] = title
                        }
                    } label: {
                        HStack(spacing: 12) {
                            VStack(alignment: .leading, spacing: 2) {
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
                                    .accessibilityLabel(Text("Ajouté à \(title)"))
                            }
                        }
                    }
                    .disabled(added[account.id] != nil)
                    .accessibilityIdentifier("addOtp.account.\(account.id)")
                }
            } footer: {
                Text("\(request.accounts.count) codes dans cet export. Chacun va dans son propre élément Login.")
            }
        }
        .navigationTitle("Ajouter des codes")
        #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
    }
}

/// One account: its live code, "Nouvel élément Login", then the Logins to attach it to.
private struct OtpAccountTarget: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let account: OtpLinkAccount
    /// Called with the Login's title once the code is stored.
    let onAdded: (String) -> Void
    @State private var query = ""
    @State private var busy = false
    @State private var replacing: FfiItemSummary?

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
                    VStack(alignment: .leading, spacing: 2) {
                        Text(account.title)
                        if let name = account.account, name != account.title {
                            Text(name).font(.footnote).foregroundStyle(.secondary)
                        }
                    }
                }
            }
            Section {
                Button {
                    Task { await create() }
                } label: {
                    Label("Nouvel élément Login", systemImage: "plus.circle")
                }
                .disabled(busy || model.vaultForNewItem == nil)
                .accessibilityIdentifier("addOtp.newLogin")
            } footer: {
                Text("Titre \(account.title), dans le coffre \(vaultName).")
            }
            if !suggested.isEmpty {
                Section("Suggestions") {
                    ForEach(suggested, id: \.id) { row($0) }
                }
            }
            Section {
                if others.isEmpty {
                    (query.isEmpty ? Text("Aucun élément Login.") : Text("Aucun résultat."))
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(others, id: \.id) { row($0) }
                }
            } header: {
                query.isEmpty ? Text("Ajouter à un élément existant") : Text("Résultats")
            }
        }
        .searchable(text: $query, prompt: Text("Rechercher un élément Login"))
        .navigationTitle("Ajouter un code")
        #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
        .alert(
            Text("Remplacer le code existant ?"),
            isPresented: Binding(get: { replacing != nil }, set: { if !$0 { replacing = nil } }),
            presenting: replacing
        ) { login in
            Button("Remplacer", role: .destructive) { Task { await attach(login) } }
            Button("Annuler", role: .cancel) { replacing = nil }
        } message: { login in
            Text("\(login.title) a déjà un code à usage unique. Le nouveau le remplace.")
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
            HStack(spacing: 12) {
                ItemIcon(type: login.itemType, title: login.title, siteIcon: nil, size: 30)
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
        if await model.session.hasOtp(itemID: login.id, vaultID: login.vaultId) {
            replacing = login
        } else {
            await attach(login)
        }
    }

    private func attach(_ login: FfiItemSummary) async {
        replacing = nil
        busy = true
        defer { busy = false }
        do {
            let item = try await model.session.attachOtp(account, toItemID: login.id, vaultID: login.vaultId)
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
