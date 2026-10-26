import DesignKit
import SwiftUI
import VaultKit

/// "Pour ce site" (strict matches, with the passkeys the request accepts), then "Autres éléments"
/// (every other Login), folded until an explicit gesture or a search (spec 5 and 8: a choice
/// outside the matches always takes a gesture).
struct CandidateListView: View {
    let model: AutoFillModel
    let session: VaultSession
    let matches: [FfiAutofillCandidate]
    let others: [FfiAutofillCandidate]
    /// A one-time code list: a row fills the current code instead of the password.
    let oneTimeCode: Bool

    @State private var query = ""
    @State private var showOthers = false
    @State private var busy = false

    var body: some View {
        AutoFillScaffold(title: oneTimeCode ? Text("Codes de vérification") : Text("Choisis un compte"), model: model) {
            List {
                Section {
                    SessionErrorText(session: session)
                    if shownMatches.isEmpty {
                        Text(query.isEmpty ? "Aucun élément pour ce site." : "Aucun résultat pour ce site.")
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(shownMatches, id: \.key) { candidate in
                            rows(for: candidate)
                        }
                    }
                } header: {
                    Text("Pour ce site")
                }
                if !others.isEmpty {
                    Section {
                        if othersVisible {
                            if shownOthers.isEmpty {
                                Text("Aucun résultat.").foregroundStyle(.secondary)
                            } else {
                                ForEach(shownOthers, id: \.key) { candidate in
                                    rows(for: candidate)
                                }
                            }
                        } else {
                            Button {
                                showOthers = true
                            } label: {
                                Label("Afficher les \(others.count) autres éléments", systemImage: "chevron.down")
                            }
                            .accessibilityIdentifier("autofill.others")
                        }
                    } header: {
                        Text("Autres éléments")
                    }
                }
            }
            .searchable(text: $query, prompt: Text("Rechercher dans OnePass"))
            .disabled(busy)
        }
    }

    // MARK: - Rows

    @ViewBuilder private func rows(for candidate: FfiAutofillCandidate) -> some View {
        let fillsSecret = oneTimeCode ? candidate.hasTotp : (candidate.hasPassword || candidate.passkeys.isEmpty)
        if fillsSecret {
            Button {
                act { await model.choose(candidate) }
            } label: {
                row(candidate, detail: candidate.user, badge: oneTimeCode ? "number" : nil)
            }
            .accessibilityIdentifier(autofillIdentifier("candidate", candidate.title))
        }
        ForEach(Array(candidate.passkeys.enumerated()), id: \.offset) { index, ref in
            Button {
                act { await model.choosePasskey(ref, in: candidate) }
            } label: {
                row(candidate, detail: ref.userName.isEmpty ? candidate.user : ref.userName, badge: "person.badge.key")
            }
            .accessibilityIdentifier(
                !fillsSecret && index == 0
                    ? autofillIdentifier("candidate", candidate.title)
                    : autofillIdentifier("passkey", candidate.title) + (index == 0 ? "" : ".\(index)"))
        }
    }

    private func row(_ candidate: FfiAutofillCandidate, detail: String, badge: String?) -> some View {
        HStack(spacing: 12) {
            ItemIcon(type: .login, title: candidate.title, siteIcon: nil, size: 32)
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: candidate.title)
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                Text(verbatim: detail.isEmpty ? (candidate.url ?? "") : detail)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer(minLength: 0)
            if let badge {
                Image(systemName: badge)
                    .foregroundStyle(Theme.accent)
                    .accessibilityLabel(badge == "number" ? Text("Code de vérification") : Text("Passkey"))
            }
        }
        .contentShape(Rectangle())
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
