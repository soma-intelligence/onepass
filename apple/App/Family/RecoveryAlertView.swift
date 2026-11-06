import SwiftUI
import VaultKit

/// A recovery asked by an organizer (spec 11.5), shown on every device of the member, locked or
/// not: "<organisateur> a demandé à récupérer ton compte. Ce sera possible le <date> à <heure>. Si
/// ce n'est pas toi, annule." "Annuler" signs with this device's keys, no password.
struct RecoveryAlertBanner: View {
    @Environment(AppModel.self) private var model
    let alert: FfiRecoveryAlert
    @State private var errorMessage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label {
                Text(VaultSession.recoveryAlertMessage(alert))
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("recovery.alert.message")
            } icon: {
                Image(systemName: "exclamationmark.shield.fill").foregroundStyle(.orange)
            }
            if let keys = model.deviceKeys {
                Button("recovery.alert.cancel", role: .destructive) {
                    Task {
                        do {
                            try await model.session.cancelRecovery(alert.enrollmentId, keys: keys)
                        } catch {
                            errorMessage = VaultError(error).localizedMessage
                        }
                    }
                }
                .accessibilityIdentifier("recovery.alert.cancel")
            }
            if let errorMessage { Text(errorMessage).font(.footnote).foregroundStyle(.red) }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
        // A container: the identifier must not replace the message's and the button's own.
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("recovery.alert")
    }
}
