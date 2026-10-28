#if os(iOS)
import DesignKit
import SwiftUI
import VaultKit

/// Public request (spec 2b 4.3): the items to lend (search, several at once) and the duration
/// (15 min by default, 60 at most), then a fresh presence check and the grant.
struct PublicSessionPicker: View {
    @Environment(AppModel.self) private var model
    let flow: PairingApproverFlow
    @State private var query = ""
    @State private var selected: Set<FfiItemRef> = []
    @State private var minutes = 15
    @State private var password = ""
    @State private var lending = false

    static let durations = [5, 10, 15, 30, 45, 60]

    private var items: [FfiItemSummary] {
        model.session.items(filter: .all, query: query, sort: .title)
    }

    var body: some View {
        Form {
            Section {
                Picker("Durée", selection: $minutes) {
                    ForEach(Self.durations, id: \.self) { value in
                        Text("\(value) min").tag(value)
                    }
                }
                .accessibilityIdentifier("approve.public.duration")
            } footer: {
                Text("La session se termine aussi si tu la termines d'ici, si le nouvel appareil passe en arrière-plan ou après 5 min sans activité.")
            }
            Section {
                ForEach(items, id: \.id) { item in
                    let ref = FfiItemRef(vaultId: item.vaultId, itemId: item.id)
                    let on = selected.contains(ref)
                    Button {
                        if on { selected.remove(ref) } else { selected.insert(ref) }
                    } label: {
                        HStack(spacing: 12) {
                            ItemIcon(type: item.itemType, title: item.title, siteIcon: nil, size: 30)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(item.title).foregroundStyle(.primary).lineLimit(1)
                                if !item.subtitle.isEmpty {
                                    Text(item.subtitle).font(.footnote).foregroundStyle(.secondary).lineLimit(1)
                                }
                            }
                            Spacer(minLength: 0)
                            Image(systemName: on ? "checkmark.circle.fill" : "circle")
                                .font(.title3)
                                .foregroundStyle(on ? Theme.accent : .secondary)
                        }
                        .contentShape(.rect)
                    }
                    .buttonStyle(.plain)
                    .accessibilityAddTraits(on ? .isSelected : [])
                    .accessibilityIdentifier("approve.public.item.\(item.id)")
                }
            } header: {
                Text("Éléments à prêter")
            } footer: {
                Text("En lecture seule, sans historique des mots de passe ni passkey. Rien n'est enregistré sur le nouvel appareil.")
            }
            if flow.approvalError != nil {
                Section {
                    SecureField("Mot de passe maître", text: $password)
                        .privacySensitive()
                        .accessibilityIdentifier("approve.password")
                } footer: {
                    if let error = flow.approvalError, error != .passwordRequired {
                        Text(error.localizedMessage).foregroundStyle(.red)
                    } else {
                        Text("Confirme avec ton mot de passe maître.")
                    }
                }
            }
            Section {
                Button {
                    Task { await lend() }
                } label: {
                    HStack {
                        Text(selected.count < 2
                             ? String(localized: "Prêter \(selected.count) élément")
                             : String(localized: "Prêter \(selected.count) éléments"))
                            .font(.headline)
                        Spacer()
                        if lending { ProgressView() }
                    }
                }
                .disabled(selected.isEmpty || lending || (flow.approvalError != nil && password.isEmpty))
                .accessibilityIdentifier("approve.public.lend")
            }
        }
        .formStyle(.grouped)
        .searchable(text: $query, prompt: Text("Rechercher"))
    }

    private func lend() async {
        lending = true
        defer { lending = false }
        let refs = Array(selected)
        let duration = UInt32(min(60, max(1, minutes)))
        if flow.approvalError != nil, !password.isEmpty {
            let typed = SecretBytes(utf8: password)
            password = ""
            defer { typed.wipe() }
            await flow.approvePublic(items: refs, minutes: duration, password: typed)
        } else {
            await flow.approvePublic(items: refs, minutes: duration)
        }
    }
}
#endif
