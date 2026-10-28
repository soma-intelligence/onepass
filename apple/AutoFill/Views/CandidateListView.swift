import DesignKit
import SwiftUI
import VaultKit

/// "Pour ce site" (strict matches, with the passkeys the request accepts) first, then "Autres
/// éléments" (every other Login), folded until an explicit gesture or a search (spec 5 and 8: a
/// choice outside the matches always takes a gesture). Rows as in the app: site icon or category
/// artwork, title, username, and a passkey or code glyph.
struct CandidateListView: View {
    let model: AutoFillModel
    let session: VaultSession
    let matches: [FfiAutofillCandidate]
    let others: [FfiAutofillCandidate]
    /// A one-time code list: a row fills the current code instead of the password.
    let oneTimeCode: Bool
    /// The site or app asking, for the heading ("pour exemple.fr").
    var site: String?

    @State private var query = ""
    @State private var showOthers = false
    @State private var busy = false
    #if os(iOS)
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    #endif

    var body: some View {
        AutoFillScaffold(title: oneTimeCode ? Text("Codes de vérification") : Text("Choisis un compte"), model: model) {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 8) {
                    SessionErrorText(session: session)
                        .padding(.horizontal, 6)
                    matchesSection
                    if !others.isEmpty {
                        othersSection
                            .padding(.top, 14)
                    }
                }
                .padding(.horizontal, 16)
                .padding(.top, 6)
                .padding(.bottom, 24)
            }
            .scrollDismissesKeyboard(.immediately)
            .searchable(text: $query, prompt: Text("Rechercher dans OnePass"))
            .disabled(busy)
        }
    }

    // MARK: - Sections

    @ViewBuilder private var matchesSection: some View {
        if let site {
            AutoFillLabel("pour \(site)")
        } else {
            AutoFillLabel("pour ce site")
        }
        if shownMatches.isEmpty {
            HStack(spacing: 12) {
                Image(systemName: "globe")
                    .font(.system(size: 17, weight: .medium))
                    .foregroundStyle(.secondary)
                    .frame(width: 36, height: 36)
                    .background(Color.primary.opacity(0.06), in: .rect(cornerRadius: 9, style: .continuous))
                Text(query.isEmpty ? "Aucun élément pour ce site." : "Aucun résultat pour ce site.")
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
        AutoFillLabel("autres éléments")
        if othersVisible {
            if shownOthers.isEmpty {
                Text("Aucun résultat.")
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
                    Text("Afficher les \(others.count) autres éléments")
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

    @ViewBuilder private func rows(for candidate: FfiAutofillCandidate) -> some View {
        let fillsSecret = oneTimeCode ? candidate.hasTotp : (candidate.hasPassword || candidate.passkeys.isEmpty)
        if fillsSecret {
            Button {
                act { await model.choose(candidate) }
            } label: {
                row(candidate, detail: candidate.user, badge: oneTimeCode ? .code : nil)
            }
            .buttonStyle(AutoFillRowStyle())
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
                Label("Code", systemImage: "number")
                    .labelStyle(.iconOnly)
                    .font(.system(size: 13, weight: .bold))
                    .foregroundStyle(Theme.readableAccent)
                    .frame(width: 28, height: 28)
                    .background(Theme.accent.opacity(0.12), in: Circle())
                    .accessibilityLabel(Text("Code de vérification"))
            case .passkey:
                HStack(spacing: 4) {
                    Image(systemName: "person.badge.key.fill")
                    Text("Passkey")
                }
                .font(.caption.weight(.semibold))
                .foregroundStyle(Theme.readableAccent)
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(Theme.accent.opacity(0.12), in: Capsule())
                .accessibilityElement(children: .ignore)
                .accessibilityLabel(Text("Passkey"))
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
