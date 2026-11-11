import DesignKit
import SwiftUI
import VaultKit

/// "Pour ce site" (strict matches, with the passkeys the request accepts) first, then "Autres
/// éléments" (every other Login), folded until an explicit gesture or a search (spec 5 and 8: a
/// choice outside the matches always takes a gesture). Rows as in the app: site icon or category
/// artwork, title, username, and a passkey or code glyph.
///
/// Without any service (an app without associated domain, G8) there is nothing to match: the list
/// opens on the search, focused, with the Logins used last first. "Nouveau login" creates, saves and
/// fills a Login with a generated password (MACAPP-03). With several accounts, a menu switches the
/// account (MACAPP-06). On the Mac, the arrows move a selection and Return fills it (MACAPP-08).
///
/// A Login picked from the other items while an app asks (its App ID came with the request) is
/// offered once to be kept for that app: "Always use for this app" writes the App ID into the
/// Login, which is then a match there; "Just this once" only fills. Never bound without the tap.
/// The dialog names the app and shows its App ID, the only part the app does not choose freely.
struct CandidateListView: View {
    let model: AutoFillModel
    let session: VaultSession
    let matches: [FfiAutofillCandidate]
    let others: [FfiAutofillCandidate]
    /// A one-time code list: a row fills the current code instead of the password.
    let oneTimeCode: Bool
    /// The site or app asking, for the heading ("pour exemple.fr").
    var site: String?
    var accounts: AutoFillAccounts?
    var switchAccount: (@MainActor (String) -> Void)?

    @State private var query = ""
    @State private var showOthers = false
    @State private var busy = false
    @State private var creating = false
    @FocusState private var searchFocused: Bool
    /// The keyboard selection (Mac): an index in `keyboardRows`.
    @State private var selection = 0
    /// A Login picked from the other items that the asking app can remember.
    @State private var bindOffer: BindOffer?

    private struct BindOffer {
        let candidate: FfiAutofillCandidate
        let app: AutoFillService
    }
    #if os(iOS)
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    #endif

    var body: some View {
        AutoFillScaffold(title: oneTimeCode ? Text("views.verificationCodes") : Text("views.chooseAccount"), model: model) {
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 8) {
                        if let accounts, accounts.accounts.count > 1 {
                            accountMenu(accounts)
                        }
                        SessionErrorText(session: session)
                            .padding(.horizontal, 6)
                        if model.listWithoutService {
                            newLoginCard
                        } else {
                            matchesSection
                            if shownMatches.isEmpty && model.canCreateLogin { newLoginCard }
                        }
                        if !others.isEmpty {
                            othersSection
                                .padding(.top, model.listWithoutService ? 0 : 14)
                        }
                        if !shownMatches.isEmpty && !model.listWithoutService && model.canCreateLogin {
                            newLoginCard
                                .padding(.top, 14)
                        }
                    }
                    .padding(.horizontal, 16)
                    .padding(.top, 6)
                    .padding(.bottom, 24)
                }
                .scrollDismissesKeyboard(.immediately)
                .searchable(text: $query, prompt: Text("views.searchOnepass"))
                .searchFocused($searchFocused)
                // Return in a search the user typed fills the first row it shows.
                .onSubmit(of: .search) { if !query.isEmpty { fillSelection() } }
                #if os(macOS)
                .onKeyPress(.downArrow) { moveSelection(1, proxy) }
                .onKeyPress(.upArrow) { moveSelection(-1, proxy) }
                .onKeyPress(.return) {
                    fillSelection()
                    return .handled
                }
                .background {
                    // Command-F: the search field.
                    Button("views.searchOnepass") { searchFocused = true }
                        .keyboardShortcut("f", modifiers: .command)
                        .hidden()
                }
                #endif
                .onChange(of: query) { selection = 0 }
                .disabled(busy)
            }
            .navigationDestination(isPresented: $creating) {
                NewLoginView(model: model, session: session, site: site)
            }
        }
        .onAppear {
            // No service: every Login is a manual choice, the search is where to start (G8).
            if model.listWithoutService {
                showOthers = true
                searchFocused = true
            }
        }
        .confirmationDialog(
            Text("views.alwaysUse.title \(bindOffer?.app.shownName ?? "")"),
            isPresented: Binding(get: { bindOffer != nil }, set: { if !$0 { bindOffer = nil } }),
            titleVisibility: .visible, presenting: bindOffer
        ) { offer in
            Button("views.alwaysUse.confirm") {
                act { await model.choose(offer.candidate, alwaysForApp: true) }
            }
            .accessibilityIdentifier("autofill.alwaysUse.confirm")
            Button("views.alwaysUse.once") {
                act { await model.choose(offer.candidate) }
            }
            .accessibilityIdentifier("autofill.alwaysUse.once")
            Button("common.cancel", role: .cancel) {}
        } message: { offer in
            // The App ID as the system gave it, under the name the app chose for itself: a
            // look-alike name cannot pass for another app.
            Text("views.alwaysUse.detail \(offer.app.identifier)")
        }
    }

    /// Fills `candidate`, after asking whether the app should remember it when it can.
    private func pick(_ candidate: FfiAutofillCandidate) {
        if let app = model.rememberableApp(for: candidate) {
            bindOffer = BindOffer(candidate: candidate, app: app)
        } else {
            act { await model.choose(candidate) }
        }
    }

    // MARK: - Account switcher (MACAPP-06)

    private func accountMenu(_ accounts: AutoFillAccounts) -> some View {
        let current = accounts.accounts.first { $0.slot == accounts.current }
        return Menu {
            ForEach(accounts.accounts) { account in
                Button {
                    guard account.slot != accounts.current else { return }
                    switchAccount?(account.slot)
                } label: {
                    if account.slot == accounts.current {
                        Label(AutoFillAccounts.name(account), systemImage: "checkmark")
                    } else {
                        Label(AutoFillAccounts.name(account), systemImage: account.symbol)
                    }
                }
                .accessibilityIdentifier("autofill.account.\(account.slot)")
            }
        } label: {
            HStack(spacing: 6) {
                Image(systemName: current?.symbol ?? "person.fill")
                Text("views.accountMenu \(current.map(AutoFillAccounts.name) ?? "")")
                Image(systemName: "chevron.up.chevron.down")
                    .font(.caption.weight(.semibold))
            }
            .font(.subheadline.weight(.medium))
        }
        .menuStyle(.button)
        .buttonStyle(.bordered)
        .controlSize(.small)
        .padding(.horizontal, 2)
        .padding(.bottom, 4)
        .accessibilityIdentifier("autofill.accounts")
    }

    // MARK: - New Login (MACAPP-03)

    @ViewBuilder private var newLoginCard: some View {
        if model.canCreateLogin {
            Button {
                creating = true
            } label: {
                HStack(spacing: 12) {
                    Image(systemName: "plus")
                        .font(.system(size: 15, weight: .bold))
                        .foregroundStyle(Theme.accent)
                        .frame(width: 36, height: 36)
                        .background(Theme.accent.opacity(0.12), in: .rect(cornerRadius: 9, style: .continuous))
                    if let site {
                        Text("views.newLoginFor \(site)")
                            .font(.body.weight(.medium))
                            .foregroundStyle(Theme.accent)
                    } else {
                        Text("views.newLogin")
                            .font(.body.weight(.medium))
                            .foregroundStyle(Theme.accent)
                    }
                    Spacer(minLength: 0)
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 10)
            }
            .buttonStyle(AutoFillRowStyle())
            .autofillCard()
            .accessibilityIdentifier("autofill.newLogin")
        }
    }

    // MARK: - Sections

    @ViewBuilder private var matchesSection: some View {
        if let site {
            AutoFillLabel("views.forSite \(site)")
        } else {
            AutoFillLabel("views.forThisSite")
        }
        if shownMatches.isEmpty {
            HStack(spacing: 12) {
                Image(systemName: "globe")
                    .font(.system(size: 17, weight: .medium))
                    .foregroundStyle(.secondary)
                    .frame(width: 36, height: 36)
                    .background(Color.primary.opacity(0.06), in: .rect(cornerRadius: 9, style: .continuous))
                Text(query.isEmpty ? "views.noItemsForSite" : "views.noResultsForSite")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            .autofillCard()
        } else {
            AutoFillCardRows {
                ForEach(shownMatches, id: \.key) { candidate in
                    rows(for: candidate)
                }
            }
        }
    }

    @ViewBuilder private var othersSection: some View {
        if model.listWithoutService {
            AutoFillLabel("views.recentItems")
        } else {
            AutoFillLabel("views.otherItems")
        }
        if othersVisible {
            if shownOthers.isEmpty {
                Text("views.noResults")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .padding(14)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .autofillCard()
            } else {
                AutoFillCardRows {
                    ForEach(shownOthers, id: \.key) { candidate in
                        rows(for: candidate)
                    }
                }
                #if os(iOS)
                // The button card gives way to the rows, which settle in from under the label.
                .transition(Motion.reveal(reduceMotion: reduceMotion))
                #endif
            }
        } else {
            Button {
                #if os(iOS)
                withAnimation(Motion.fold(reduceMotion: reduceMotion)) { showOthers = true }
                #else
                withAnimation(.snappy) { showOthers = true }
                #endif
            } label: {
                HStack(spacing: 12) {
                    Image(systemName: "chevron.down")
                        .font(.system(size: 14, weight: .bold))
                        .foregroundStyle(Theme.accent)
                        .frame(width: 36, height: 36)
                        .background(Theme.accent.opacity(0.12), in: .rect(cornerRadius: 9, style: .continuous))
                    Text("views.showMoreItems \(others.count)")
                        .font(.body.weight(.medium))
                        .foregroundStyle(Theme.accent)
                    Spacer(minLength: 0)
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 10)
            }
            .buttonStyle(AutoFillRowStyle())
            .autofillCard()
            #if os(iOS)
            .transition(.opacity)
            #endif
            .accessibilityIdentifier("autofill.others")
        }
    }

    // MARK: - Rows

    private func fillsSecret(_ candidate: FfiAutofillCandidate) -> Bool {
        oneTimeCode ? candidate.hasTotp : (candidate.hasPassword || candidate.passkeys.isEmpty)
    }

    @ViewBuilder private func rows(for candidate: FfiAutofillCandidate) -> some View {
        let fillsSecret = fillsSecret(candidate)
        if fillsSecret {
            Button {
                pick(candidate)
            } label: {
                row(candidate, detail: candidate.user, badge: oneTimeCode ? .code : nil)
                    .background(selectedKey == candidate.key ? Theme.accent.opacity(0.14) : .clear)
            }
            .buttonStyle(AutoFillRowStyle())
            .id(candidate.key)
            .accessibilityIdentifier(autofillIdentifier("candidate", candidate.title))
        }
        ForEach(Array(candidate.passkeys.enumerated()), id: \.offset) { index, ref in
            Button {
                act { await model.choosePasskey(ref, in: candidate) }
            } label: {
                row(candidate, detail: ref.userName.isEmpty ? candidate.user : ref.userName, badge: .passkey)
            }
            .buttonStyle(AutoFillRowStyle())
            .accessibilityIdentifier(
                !fillsSecret && index == 0
                    ? autofillIdentifier("candidate", candidate.title)
                    : autofillIdentifier("passkey", candidate.title) + (index == 0 ? "" : ".\(index)"))
        }
    }

    private enum Badge { case code, passkey }

    private func row(_ candidate: FfiAutofillCandidate, detail: String, badge: Badge?) -> some View {
        AutoFillRow(
            type: .login, title: candidate.title, detail: detail.isEmpty ? (candidate.url ?? "") : detail,
            url: candidate.url
        ) {
            switch badge {
            case .code:
                Label("views.code", systemImage: "number")
                    .labelStyle(.iconOnly)
                    .font(.system(size: 13, weight: .bold))
                    .foregroundStyle(Theme.readableAccent)
                    .frame(width: 28, height: 28)
                    .background(Theme.accent.opacity(0.12), in: Circle())
                    .accessibilityLabel(Text("views.verificationCode"))
            case .passkey:
                HStack(spacing: 4) {
                    Image(systemName: "person.badge.key.fill")
                    Text("term.passkey")
                }
                .font(.caption.weight(.semibold))
                .foregroundStyle(Theme.readableAccent)
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(Theme.accent.opacity(0.12), in: Capsule())
                .accessibilityElement(children: .ignore)
                .accessibilityLabel(Text("term.passkey"))
            case nil:
                EmptyView()
            }
        }
    }

    private func act(_ action: @escaping @MainActor () async -> Void) {
        guard !busy else { return }
        busy = true
        session.lastError = nil
        Task {
            await action()
            busy = false
        }
    }

    // MARK: - Keyboard (Mac, MACAPP-08)

    /// The rows the arrows walk: the matches, then the others once shown.
    private var keyboardRows: [FfiAutofillCandidate] {
        shownMatches + (othersVisible ? shownOthers : [])
    }

    /// The selected row; none on iOS (touch has no selection).
    private var selectedKey: String? {
        #if os(macOS)
        let rows = keyboardRows
        return rows.indices.contains(selection) ? rows[selection].key : nil
        #else
        return nil
        #endif
    }

    private func moveSelection(_ step: Int, _ proxy: ScrollViewProxy) -> KeyPress.Result {
        let rows = keyboardRows
        guard !rows.isEmpty else { return .ignored }
        selection = min(max(selection + step, 0), rows.count - 1)
        proxy.scrollTo(rows[selection].key)
        return .handled
    }

    /// Return (or the search's submit): fills the selected row (the first one when nothing moved),
    /// its first offered passkey for a passkey-only Login.
    private func fillSelection() {
        let rows = keyboardRows
        guard rows.indices.contains(selection) else { return }
        let candidate = rows[selection]
        if fillsSecret(candidate) {
            pick(candidate)
        } else if let ref = candidate.passkeys.first {
            act { await model.choosePasskey(ref, in: candidate) }
        }
    }

    // MARK: - Search

    private var othersVisible: Bool { showOthers || !query.isEmpty }
    private var shownMatches: [FfiAutofillCandidate] { matches.filter(matchesQuery) }
    private var shownOthers: [FfiAutofillCandidate] { others.filter(matchesQuery) }

    private func matchesQuery(_ candidate: FfiAutofillCandidate) -> Bool {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !needle.isEmpty else { return true }
        return [candidate.title, candidate.user, candidate.url ?? ""]
            .contains { $0.localizedStandardContains(needle) }
    }
}

extension FfiAutofillCandidate {
    /// Unique per item across vaults.
    var key: String { "\(vaultId):\(itemId)" }
}
