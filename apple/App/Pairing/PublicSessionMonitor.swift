#if os(iOS)
import DesignKit
import SwiftUI
import VaultKit

/// A running public session seen from the approver: the time left, the journal (item opened, field
/// copied, never a value) and "Terminer la session". The journal lives in memory until the end.
struct PublicSessionMonitor: View {
    let flow: PairingApproverFlow

    private var journal: [PairingAuditEntry] {
        if case .publicRunning(let journal, _) = flow.state { return journal.reversed() }
        return []
    }

    private var countdown: String {
        let left = Int(flow.remaining.rounded(.up))
        if left >= 60 {
            let minutes = Int((Double(left) / 60).rounded(.up))
            return String(localized: "Se termine dans \(minutes) min")
        }
        return String(localized: "Se termine dans \(left) s")
    }

    var body: some View {
        Form {
            Section {
                Label {
                    Text(countdown)
                        .font(.headline)
                        .monospacedDigit()
                        .contentTransition(.numericText())
                        .accessibilityIdentifier("approve.monitor.countdown")
                } icon: {
                    Image(systemName: "person.badge.clock").foregroundStyle(.orange)
                }
            } header: {
                Text("Session invitée en cours")
            }
            Section {
                if journal.isEmpty {
                    Text("Rien n'a encore été ouvert.")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(journal) { entry in
                        HStack(spacing: 12) {
                            Image(systemName: Self.symbol(entry.action))
                                .foregroundStyle(.secondary)
                                .frame(width: 22)
                                .accessibilityHidden(true)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(entry.title.isEmpty ? String(localized: "Élément") : entry.title).lineLimit(1)
                                Text(Self.label(entry.action)).font(.footnote).foregroundStyle(.secondary)
                            }
                            Spacer(minLength: 0)
                            Text(entry.at.formatted(date: .omitted, time: .shortened))
                                .font(.footnote.monospacedDigit())
                                .foregroundStyle(.secondary)
                        }
                        .accessibilityElement(children: .combine)
                    }
                }
            } header: {
                Text("Journal")
            } footer: {
                Text("Le journal disparaît à la fin de la session.")
            }
            Section {
                Button("Terminer la session", role: .destructive) {
                    Task { await flow.endPublicSession() }
                }
                .accessibilityIdentifier("approve.monitor.end")
            }
        }
        .formStyle(.grouped)
    }

    private static func symbol(_ action: FfiAuditAction) -> String {
        switch action {
        case .opened: "eye"
        case .copied: "doc.on.doc"
        }
    }

    private static func label(_ action: FfiAuditAction) -> String {
        switch action {
        case .opened: String(localized: "Ouvert")
        case .copied(let label): String(localized: "Copié : \(label)")
        }
    }
}
#endif
