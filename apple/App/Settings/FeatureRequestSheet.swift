import DesignBridgeKit
import DesignKit
import SwiftUI
import VaultKit

/// Réglages > Suggérer une fonctionnalité: the person types an idea, may leave an email, and Envoyer
/// sends both to Soma Labs (`FeatureRequestClient`). Built like the other sheets of Réglages (a
/// grouped form, Annuler and the action in the toolbar, the error inline). Nothing from the vault
/// is read or sent. On an error the text stays, so nothing typed is lost.
struct FeatureRequestSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var message = ""
    @State private var email = ""
    @State private var phase = Phase.editing
    @State private var failure: FeatureRequestError?
    @FocusState private var messageFocused: Bool

    var client = FeatureRequestClient()

    enum Phase: Equatable {
        case editing, sending, sent
    }

    static let table = "FeatureRequest"
    /// How long the thank-you line stays before the sheet closes.
    private static let thanksDelay: Duration = .seconds(1.6)

    private var canSend: Bool { phase == .editing && FeatureRequestClient.canSend(message) }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField(text: $message, prompt: Text("featureRequest.message.prompt", tableName: Self.table),
                              axis: .vertical) {
                        Text("featureRequest.message.label", tableName: Self.table)
                    }
                    .lineLimit(5 ... 12)
                    .focused($messageFocused)
                    .disabled(phase != .editing)
                    .accessibilityLabel(Text("featureRequest.message.label", tableName: Self.table))
                    .accessibilityIdentifier("settings.featureRequest.message")
                } footer: {
                    Text("featureRequest.count \(message.count)", tableName: Self.table)
                        .monospacedDigit()
                        .frame(maxWidth: .infinity, alignment: .trailing)
                        .accessibilityLabel(Text("featureRequest.count.a11y \(message.count)", tableName: Self.table))
                        .accessibilityIdentifier("settings.featureRequest.count")
                }
                Section {
                    TextField(text: $email, prompt: Text("featureRequest.email.prompt", tableName: Self.table)) {
                        Text("featureRequest.email.label", tableName: Self.table)
                    }
                    .textContentType(.emailAddress)
                    #if os(iOS) || os(visionOS)
                    .keyboardType(.emailAddress)
                    .textInputAutocapitalization(.never)
                    #endif
                    .autocorrectionDisabled()
                    .disabled(phase != .editing)
                    .onSubmit(send)
                    .accessibilityLabel(Text("featureRequest.email.label", tableName: Self.table))
                    .accessibilityIdentifier("settings.featureRequest.email")
                } footer: {
                    Text("featureRequest.footer", tableName: Self.table)
                }
                if phase == .sent {
                    Section {
                        Label {
                            Text("featureRequest.sent", tableName: Self.table)
                        } icon: {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundStyle(.green)
                                .accessibilityHidden(true)
                        }
                        .accessibilityIdentifier("settings.featureRequest.sent")
                    }
                } else if let failure {
                    Section {
                        Label {
                            Text(Self.errorKey(failure), tableName: Self.table)
                        } icon: {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .accessibilityHidden(true)
                        }
                        .foregroundStyle(.red)
                        .accessibilityIdentifier("settings.featureRequest.error")
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle(Text("featureRequest.title", tableName: Self.table))
            #if os(iOS) || os(visionOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Annuler") { dismiss() }
                        .disabled(phase == .sending)
                        .accessibilityIdentifier("settings.featureRequest.cancel")
                }
                ToolbarItem(placement: .confirmationAction) {
                    if phase == .sending {
                        ProgressView()
                            .accessibilityLabel(Text("featureRequest.sending", tableName: Self.table))
                            .accessibilityIdentifier("settings.featureRequest.sending")
                    } else {
                        Button(action: send) {
                            Text("featureRequest.send", tableName: Self.table)
                        }
                        .disabled(!canSend)
                        .accessibilityIdentifier("settings.featureRequest.send")
                    }
                }
            }
        }
        #if os(macOS)
        .frame(minWidth: 420, minHeight: 380)
        #endif
        .interactiveDismissDisabled(phase == .sending)
        .dbHaptic(.success, trigger: phase == .sent)
        .onChange(of: message) {
            if message.count > FeatureRequestClient.maximumLength {
                message = String(message.prefix(FeatureRequestClient.maximumLength))
            }
            if failure == .messageTooShort || failure == .messageTooLong { failure = nil }
        }
        .onChange(of: email) {
            if failure == .invalidEmail { failure = nil }
        }
        .onAppear { messageFocused = true }
        .task(id: phase) {
            guard phase == .sent else { return }
            try? await Task.sleep(for: Self.thanksDelay)
            dismiss()
        }
    }

    private func send() {
        guard canSend else { return }
        failure = nil
        phase = .sending
        let idea = FeatureRequest.current(message: message, email: email)
        Task {
            do throws(FeatureRequestError) {
                try await client.send(idea)
                phase = .sent
            } catch {
                failure = error
                phase = .editing
            }
        }
    }

    static func errorKey(_ error: FeatureRequestError) -> LocalizedStringKey {
        switch error {
        case .messageTooShort: "featureRequest.error.tooShort"
        case .messageTooLong: "featureRequest.error.tooLong"
        case .invalidEmail: "featureRequest.error.invalidEmail"
        case .rateLimited: "featureRequest.error.rateLimited"
        case .server: "featureRequest.error.server"
        case .network: "featureRequest.error.network"
        }
    }
}
