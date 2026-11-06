import SwiftUI
import VaultKit

/// On the member's new device (spec 11.5): "J'ai perdu mon mot de passe ou ma Secret Key", then
/// "Demander l'aide de <organisateur>": the QR for the organizer, the code to compare, a new master
/// password, then the new Secret Key for a new Emergency Kit.
struct RecoverWithHelpView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Group {
                if let keys = model.deviceKeys {
                    RecoverContent(keys: keys)
                } else {
                    DeviceKeysUnavailableView()
                }
            }
            .navigationTitle(Text("recovery.lost"))
            #if os(iOS) || os(visionOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Annuler") { dismiss() } }
            }
        }
    }
}

private struct RecoverContent: View {
    @Environment(AppModel.self) private var model
    let keys: any DeviceKeySource
    @StateObject private var holder = Holder()
    @State private var newPassword = ""
    @State private var kitKey = ""

    var body: some View {
        Form {
            if let flow = holder.flow {
                StateView(flow: flow, newPassword: $newPassword, kitKey: $kitKey, needsKit: model.syncsThroughMailbox, keys: keys)
            } else {
                Section {
                    Button("recovery.askHelp.start") {
                        let flow = RecoverWithHelpFlow(
                            dbPath: model.session.environment.databaseURL.path, keychain: model.session.environment.keychain)
                        holder.flow = flow
                        flow.start()
                    }
                }
            }
        }
    }

    @MainActor final class Holder: ObservableObject {
        @Published var flow: RecoverWithHelpFlow?
    }

    private struct StateView: View {
        @ObservedObject var flow: RecoverWithHelpFlow
        @Binding var newPassword: String
        @Binding var kitKey: String
        let needsKit: Bool
        let keys: any DeviceKeySource

        var body: some View {
            switch flow.state {
            case .idle, .waitingForOrganizer:
                Section { ProgressView().frame(maxWidth: .infinity) }
            case .showingQR(let text):
                Section {
                    if let image = PairingQRView.image(text, side: 600) {
                        Image(decorative: image, scale: 1).interpolation(.none).resizable()
                            .aspectRatio(1, contentMode: .fit).frame(maxWidth: 260).frame(maxWidth: .infinity)
                    }
                }
            case .comparing(let sas):
                Section {
                    Text(sas).font(.system(size: 34, weight: .bold, design: .monospaced)).frame(maxWidth: .infinity)
                } footer: {
                    Text("sharing.verify.compare")
                }
                Section {
                    SecureField("recovery.newPassword", text: $newPassword)
                    if needsKit { TextField("recovery.kitSecretKey", text: $kitKey) }
                    Button("sharing.verify.same") {
                        flow.confirm(
                            newPassword: newPassword, kitSecretKey: needsKit ? kitKey : nil, keys: keys,
                            deviceName: VaultSession.currentDeviceName(), kind: VaultSession.currentDeviceKind, mode: .personal)
                        newPassword = ""
                    }
                    .disabled(newPassword.isEmpty)
                    Button("sharing.verify.different", role: .destructive) { flow.reject() }
                }
            case .done(let key):
                Section {
                    Text("recovery.done")
                    Text(key).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                } footer: {
                    Text("recovery.done.footer")
                }
            case .failed(let failure):
                Section { Label(failure.message, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red) }
            }
        }
    }
}
